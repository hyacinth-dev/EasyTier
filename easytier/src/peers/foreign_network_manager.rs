/*
foreign_network_manager is used to forward packets of other networks.  currently
only forward packets of peers that directly connected to this node.

in future, with the help wo peer center we can forward packets of peers that
connected to any node in the local network.
*/
use std::{
    ops::AddAssign,
    sync::{Arc, Weak},
    time::SystemTime,
};

use dashmap::DashMap;
use tokio::{
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
    task::JoinSet,
};

use sqlx::{Executor, MySqlPool, Row};

use crate::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtx, GlobalCtxEvent, NetworkIdentity},
        join_joinset_background,
        stun::MockStunInfoCollector,
        PeerId,
    },
    peers::route_trait::{Route, RouteInterface},
    proto::{
        cli::{ForeignNetworkEntryPb, ListForeignNetworkResponse, PeerInfo},
        common::NatType,
        peer_rpc::DirectConnectorRpcServer,
    },
    tunnel::generate_digest_from_str,
    tunnel::packet_def::{PacketType, ZCPacket},
};

use super::{
    create_packet_recv_chan,
    peer_conn::PeerConn,
    peer_map::PeerMap,
    peer_ospf_route::PeerRoute,
    peer_rpc::{PeerRpcManager, PeerRpcManagerTransport},
    peer_rpc_service::DirectConnectorManagerRpcServer,
    recv_packet_from_chan,
    route_trait::NextHopPolicy,
    PacketRecvChan, PacketRecvChanReceiver,
};

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Box, Arc)]
pub trait GlobalForeignNetworkAccessor: Send + Sync + 'static {
    async fn list_global_foreign_peer(&self, network_identity: &NetworkIdentity) -> Vec<PeerId>;
}

pub struct ForeignNetworkEntry {
    my_peer_id: PeerId,

    global_ctx: ArcGlobalCtx,
    network: NetworkIdentity,
    pub peer_map: Arc<PeerMap>,
    relay_data: bool,
    pm_packet_sender: Mutex<Option<PacketRecvChan>>,

    peer_rpc: Arc<PeerRpcManager>,
    rpc_sender: UnboundedSender<ZCPacket>,

    packet_recv: Mutex<Option<PacketRecvChanReceiver>>,

    tasks: Mutex<JoinSet<()>>,

    ip_range: String,
    pub traffic: Arc<Mutex<u64>>,
}

impl ForeignNetworkEntry {
    fn new(
        network: NetworkIdentity,
        global_ctx: ArcGlobalCtx,
        my_peer_id: PeerId,
        relay_data: bool,
        pm_packet_sender: PacketRecvChan,
        ip_range: String,
    ) -> Self {
        let foreign_global_ctx = Self::build_foreign_global_ctx(&network, global_ctx.clone());

        let (packet_sender, packet_recv) = create_packet_recv_chan();

        let peer_map = Arc::new(PeerMap::new(
            packet_sender,
            foreign_global_ctx.clone(),
            my_peer_id,
        ));

        let (peer_rpc, rpc_transport_sender) = Self::build_rpc_tspt(my_peer_id, peer_map.clone());

        peer_rpc.rpc_server().registry().register(
            DirectConnectorRpcServer::new(DirectConnectorManagerRpcServer::new(
                foreign_global_ctx.clone(),
            )),
            &network.network_name,
        );

        Self {
            my_peer_id,

            global_ctx: foreign_global_ctx,
            network,
            peer_map,
            relay_data,
            pm_packet_sender: Mutex::new(Some(pm_packet_sender)),

            peer_rpc,
            rpc_sender: rpc_transport_sender,

            packet_recv: Mutex::new(Some(packet_recv)),

            tasks: Mutex::new(JoinSet::new()),
            ip_range,
            traffic: Arc::new(Mutex::new(0)),
        }
    }

    fn build_foreign_global_ctx(
        network: &NetworkIdentity,
        global_ctx: ArcGlobalCtx,
    ) -> ArcGlobalCtx {
        let config = TomlConfigLoader::default();
        config.set_network_identity(network.clone());
        config.set_hostname(Some(format!("PublicServer_{}", global_ctx.get_hostname())));

        let foreign_global_ctx = Arc::new(GlobalCtx::new(config));
        foreign_global_ctx.replace_stun_info_collector(Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
        }));

        let mut feature_flag = global_ctx.get_feature_flags();
        feature_flag.is_public_server = true;
        foreign_global_ctx.set_feature_flags(feature_flag);

        for u in global_ctx.get_running_listeners().into_iter() {
            foreign_global_ctx.add_running_listener(u);
        }

        foreign_global_ctx
    }

    fn build_rpc_tspt(
        my_peer_id: PeerId,
        peer_map: Arc<PeerMap>,
    ) -> (Arc<PeerRpcManager>, UnboundedSender<ZCPacket>) {
        struct RpcTransport {
            my_peer_id: PeerId,
            peer_map: Weak<PeerMap>,

            packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
        }

        #[async_trait::async_trait]
        impl PeerRpcManagerTransport for RpcTransport {
            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }

            async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error> {
                tracing::debug!(
                    "foreign network manager send rpc to peer: {:?}",
                    dst_peer_id
                );
                let peer_map = self
                    .peer_map
                    .upgrade()
                    .ok_or(anyhow::anyhow!("peer map is gone"))?;

                // send to ourselves so we can handle it in forward logic.
                peer_map.send_msg_directly(msg, self.my_peer_id).await
            }

            async fn recv(&self) -> Result<ZCPacket, Error> {
                if let Some(o) = self.packet_recv.lock().await.recv().await {
                    tracing::info!("recv rpc packet in foreign network manager rpc transport");
                    Ok(o)
                } else {
                    Err(Error::Unknown)
                }
            }
        }

        impl Drop for RpcTransport {
            fn drop(&mut self) {
                tracing::debug!(
                    "drop rpc transport for foreign network manager, my_peer_id: {:?}",
                    self.my_peer_id
                );
            }
        }

        let (rpc_transport_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
        let tspt = RpcTransport {
            my_peer_id,
            peer_map: Arc::downgrade(&peer_map),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
        };

        let peer_rpc = Arc::new(PeerRpcManager::new(tspt));
        (peer_rpc, rpc_transport_sender)
    }

    async fn prepare_route(
        &self,
        my_peer_id: PeerId,
        accessor: Box<dyn GlobalForeignNetworkAccessor>,
    ) {
        struct Interface {
            my_peer_id: PeerId,
            peer_map: Weak<PeerMap>,
            network_identity: NetworkIdentity,
            accessor: Box<dyn GlobalForeignNetworkAccessor>,
        }

        #[async_trait::async_trait]
        impl RouteInterface for Interface {
            async fn list_peers(&self) -> Vec<PeerId> {
                let Some(peer_map) = self.peer_map.upgrade() else {
                    return vec![];
                };

                let mut global = self
                    .accessor
                    .list_global_foreign_peer(&self.network_identity)
                    .await;
                let local = peer_map.list_peers_with_conn().await;
                global.extend(local.iter().cloned());
                global
                    .into_iter()
                    .filter(|x| *x != self.my_peer_id)
                    .collect()
            }

            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }
        }

        let route = PeerRoute::new(
            my_peer_id,
            self.global_ctx.clone(),
            self.peer_rpc.clone(),
            self.ip_range.clone(),
        );
        route
            .open(Box::new(Interface {
                my_peer_id,
                network_identity: self.network.clone(),
                peer_map: Arc::downgrade(&self.peer_map),
                accessor,
            }))
            .await
            .unwrap();

        self.peer_map.add_route(Arc::new(Box::new(route))).await;
    }

    async fn start_packet_recv(&self) {
        let mut recv = self.packet_recv.lock().await.take().unwrap();
        let my_node_id = self.my_peer_id;
        let rpc_sender = self.rpc_sender.clone();
        let peer_map = self.peer_map.clone();
        let relay_data = self.relay_data;
        let pm_sender = self.pm_packet_sender.lock().await.take().unwrap();
        let network_name = self.network.network_name.clone();
        let traffic = self.traffic.clone();
        self.tasks.lock().await.spawn(async move {
            while let Ok(zc_packet) = recv_packet_from_chan(&mut recv).await {
                let Some(hdr) = zc_packet.peer_manager_header() else {
                    tracing::warn!("invalid packet, skip");
                    continue;
                };
                tracing::info!(?hdr, "recv packet in foreign network manager");
                // println!("packet len: {}", zc_packet.payload_len());
                traffic
                    .lock()
                    .await
                    .add_assign(zc_packet.payload_len() as u64);
                let to_peer_id = hdr.to_peer_id.get();
                if to_peer_id == my_node_id {
                    if hdr.packet_type == PacketType::TaRpc as u8
                        || hdr.packet_type == PacketType::RpcReq as u8
                        || hdr.packet_type == PacketType::RpcResp as u8
                    {
                        rpc_sender.send(zc_packet).unwrap();
                        continue;
                    }
                    tracing::trace!(?hdr, "ignore packet in foreign network");
                } else {
                    if !relay_data && hdr.packet_type == PacketType::Data as u8 {
                        continue;
                    }

                    let gateway_peer_id = peer_map
                        .get_gateway_peer_id(to_peer_id, NextHopPolicy::LeastHop)
                        .await;

                    if gateway_peer_id.is_some() && peer_map.has_peer(gateway_peer_id.unwrap()) {
                        if let Err(e) = peer_map
                            .send_msg_directly(zc_packet, gateway_peer_id.unwrap())
                            .await
                        {
                            tracing::error!(
                                ?e,
                                "send packet to foreign peer inside peer map failed"
                            );
                        }
                    } else {
                        let mut foreign_packet = ZCPacket::new_for_foreign_network(
                            &network_name,
                            to_peer_id,
                            &zc_packet,
                        );
                        foreign_packet.fill_peer_manager_hdr(
                            my_node_id,
                            gateway_peer_id.unwrap_or(to_peer_id),
                            PacketType::ForeignNetworkPacket as u8,
                        );
                        if let Err(e) = pm_sender.send(foreign_packet).await {
                            tracing::error!("send packet to peer with pm failed: {:?}", e);
                        }
                    }
                }
            }
        });
    }

    async fn prepare(&self, my_peer_id: PeerId, accessor: Box<dyn GlobalForeignNetworkAccessor>) {
        self.prepare_route(my_peer_id, accessor).await;
        self.start_packet_recv().await;
        self.peer_rpc.run();
    }
}

impl Drop for ForeignNetworkEntry {
    fn drop(&mut self) {
        self.peer_rpc
            .rpc_server()
            .registry()
            .unregister_by_domain(&self.network.network_name);

        tracing::debug!(self.my_peer_id, ?self.network, "drop foreign network entry");
    }
}

pub struct ForeignNetworkManagerData {
    pub network_peer_maps: DashMap<String, Arc<ForeignNetworkEntry>>,
    peer_network_map: DashMap<PeerId, String>,
    network_peer_last_update: DashMap<String, SystemTime>,
    accessor: Arc<Box<dyn GlobalForeignNetworkAccessor>>,
    lock: std::sync::Mutex<()>,
}

impl ForeignNetworkManagerData {
    fn get_peer_network(&self, peer_id: PeerId) -> Option<String> {
        self.peer_network_map.get(&peer_id).map(|v| v.clone())
    }

    pub fn get_network_entry(&self, network_name: &str) -> Option<Arc<ForeignNetworkEntry>> {
        self.network_peer_maps.get(network_name).map(|v| v.clone())
    }

    fn remove_peer(&self, peer_id: PeerId, network_name: &String) {
        let _l = self.lock.lock().unwrap();
        self.peer_network_map.remove(&peer_id);
        if let Some(_) = self
            .network_peer_maps
            .remove_if(network_name, |_, v| v.peer_map.is_empty())
        {
            self.network_peer_last_update.remove(network_name);
        }
    }

    async fn clear_no_conn_peer(&self, network_name: &String) {
        let Some(peer_map) = self
            .network_peer_maps
            .get(network_name)
            .and_then(|v| Some(v.peer_map.clone()))
        else {
            return;
        };
        peer_map.clean_peer_without_conn().await;
    }

    fn remove_network(&self, network_name: &String) {
        let _l = self.lock.lock().unwrap();
        self.peer_network_map.retain(|_, v| v != network_name);
        self.network_peer_maps.remove(network_name);
        self.network_peer_last_update.remove(network_name);
    }

    async fn get_or_insert_entry(
        &self,
        network_identity: &NetworkIdentity,
        my_peer_id: PeerId,
        dst_peer_id: PeerId,
        relay_data: bool,
        global_ctx: &ArcGlobalCtx,
        pm_packet_sender: &PacketRecvChan,
        ip_range: String,
    ) -> (Arc<ForeignNetworkEntry>, bool) {
        let mut new_added = false;

        let l = self.lock.lock().unwrap();
        let entry = self
            .network_peer_maps
            .entry(network_identity.network_name.clone())
            .or_insert_with(|| {
                new_added = true;
                Arc::new(ForeignNetworkEntry::new(
                    network_identity.clone(),
                    global_ctx.clone(),
                    my_peer_id,
                    relay_data,
                    pm_packet_sender.clone(),
                    ip_range.clone(),
                ))
            })
            .clone();

        self.peer_network_map
            .insert(dst_peer_id, network_identity.network_name.clone());

        self.network_peer_last_update
            .insert(network_identity.network_name.clone(), SystemTime::now());

        drop(l);

        if new_added {
            entry
                .prepare(my_peer_id, Box::new(self.accessor.clone()))
                .await;
        }

        (entry, new_added)
    }
}

pub const FOREIGN_NETWORK_SERVICE_ID: u32 = 1;

pub struct ForeignNetworkManager {
    my_peer_id: PeerId,
    global_ctx: ArcGlobalCtx,
    packet_sender_to_mgr: PacketRecvChan,

    pub data: Arc<ForeignNetworkManagerData>,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    pool: Option<Arc<MySqlPool>>,
}

impl ForeignNetworkManager {
    pub fn new(
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        packet_sender_to_mgr: PacketRecvChan,
        accessor: Box<dyn GlobalForeignNetworkAccessor>,
        pool: Option<Arc<MySqlPool>>,
    ) -> Self {
        let data = Arc::new(ForeignNetworkManagerData {
            network_peer_maps: DashMap::new(),
            peer_network_map: DashMap::new(),
            network_peer_last_update: DashMap::new(),
            accessor: Arc::new(accessor),
            lock: std::sync::Mutex::new(()),
        });

        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "ForeignNetworkManager".to_string());

        Self {
            my_peer_id,
            global_ctx,
            packet_sender_to_mgr,

            data,

            tasks,

            pool,
        }
    }

    pub async fn add_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        tracing::info!(peer_conn = ?peer_conn.get_conn_info(), network = ?peer_conn.get_network_identity(), "add new peer conn in foreign network manager");
        // println!(
        //     "add new peer conn in foreign network manager: {:?}",
        //     peer_conn.get_network_identity()
        // );
        let relay_peer_rpc = self.global_ctx.get_flags().relay_all_peer_rpc;
        let ret = self
            .global_ctx
            .check_network_in_whitelist(&peer_conn.get_network_identity().network_name)
            .map_err(Into::into);
        if ret.is_err() && !relay_peer_rpc {
            return ret;
        }

        let mut clients_limit = i32::MAX;
        let mut need_update = false;
        let mut ip_range = "192.168.100.0".to_string();

        if self.pool.is_some() {
            let res = self.pool.as_ref().unwrap().acquire().await;
            if let Err(e) = res {
                tracing::error!(?e, "get db connection failed");
                return Err(Error::DbError(e.to_string()));
            }
            let mut conn = res.unwrap();
            let sql = format!(
                "SELECT * FROM vnets WHERE token='{}' AND deleted_at IS NULL",
                peer_conn.get_network_identity().network_name
            );
            let row = conn.fetch_one(sql.as_str()).await;
            if let Err(e) = row {
                tracing::error!(?e, "get network failed");
                return Err(Error::DbError("找不到网络".to_string()));
            }
            let row = row.unwrap();

            let enabled = row.get::<i32, _>("enabled") == 1;
            if !enabled {
                return Err(Error::DbError("网络已被禁用".to_string()));
            }

            let user_id = row.get::<String, _>("user_id");
            let sql = format!(
                "SELECT remaining_traffic FROM users WHERE user_id='{}' AND deleted_at IS NULL",
                user_id
            );

            let traffic_row = conn.fetch_one(sql.as_str()).await;
            if let Err(e) = traffic_row {
                tracing::error!(?e, "get user traffic failed");
                return Err(Error::DbError("获取用户流量失败".to_string()));
            }

            let remaining_traffic = traffic_row.unwrap().get::<i64, _>("remaining_traffic");

            if remaining_traffic <= 0 {
                return Err(Error::DbError("用户流量已用完".to_string()));
            }

            let mut db_secret_digest = [0u8; 32];
            generate_digest_from_str(
                &peer_conn.get_network_identity().network_name,
                &row.get::<String, _>("password"),
                &mut db_secret_digest,
            );

            if db_secret_digest
                != peer_conn
                    .get_network_identity()
                    .network_secret_digest
                    .unwrap_or_default()
            {
                println!(
                    "network secret not match. exp: {:?} real: {:?}",
                    db_secret_digest,
                    peer_conn.get_network_identity().network_secret_digest
                );
                return Err(Error::DbError("网络密钥不匹配".to_string()));
            }
            // enable_
            clients_limit = row.get::<i32, _>("clients_limit");
            need_update = row.get::<i32, _>("need_update") == 1;
            let enable_dhcp = row.get::<i32, _>("enable_dhcp") == 1;
            if enable_dhcp {
                ip_range = row.get::<String, _>("ip_range");
            }

            if need_update {
                let sql = format!(
                    "UPDATE vnets SET need_update=0 WHERE token='{}' AND deleted_at IS NULL",
                    peer_conn.get_network_identity().network_name
                );
                conn.execute(sql.as_str()).await.unwrap();
            }
        }

        let (entry, new_added) = self
            .data
            .get_or_insert_entry(
                &peer_conn.get_network_identity(),
                self.my_peer_id,
                peer_conn.get_peer_id(),
                !ret.is_err(),
                &self.global_ctx,
                &self.packet_sender_to_mgr,
                ip_range,
            )
            .await;

        entry.peer_map.clean_peer_without_conn().await;

        if need_update {
            println!("检测到需要更新，将所有人逐出");
            // 将所有人逐出房间
            entry.peer_map.clean_all_peers().await;
        }

        if entry.peer_map.list_peers().await.len() >= clients_limit as usize {
            return Err(Error::DbError("房间用户数超限".to_string()));
        }
        if self.pool.is_some() {
            let res = self.pool.as_ref().unwrap().acquire().await;
            if let Err(e) = res {
                tracing::error!(?e, "get db connection failed");
                return Err(Error::DbError(e.to_string()));
            }
            let mut conn = res.unwrap();

            let sql = format!(
                "UPDATE vnets SET clients_online={} WHERE token='{}' AND deleted_at IS NULL",
                entry.peer_map.list_peers().await.len() + 1,
                peer_conn.get_network_identity().network_name
            );

            conn.execute(sql.as_str()).await.map_err(|e| {
                tracing::error!(?e, "update vnets clients failed");
                Error::DbError("更新网络用户数失败".to_string())
            })?;
        }

        if entry.network != peer_conn.get_network_identity() {
            if new_added {
                self.data
                    .remove_network(&entry.network.network_name.clone());
            }
            return Err(anyhow::anyhow!(
                "network secret not match. exp: {:?} real: {:?}",
                entry.network,
                peer_conn.get_network_identity()
            )
            .into());
        }

        if new_added {
            self.start_event_handler(&entry).await;
        }

        Ok(entry.peer_map.add_new_peer_conn(peer_conn).await)
    }

    async fn start_event_handler(&self, entry: &ForeignNetworkEntry) {
        let data = self.data.clone();
        let network_name = entry.network.network_name.clone();
        let mut s = entry.global_ctx.subscribe();
        self.tasks.lock().unwrap().spawn(async move {
            while let Ok(e) = s.recv().await {
                match &e {
                    GlobalCtxEvent::PeerRemoved(peer_id) => {
                        tracing::info!(?e, "remove peer from foreign network manager");
                        data.remove_peer(*peer_id, &network_name);
                        data.network_peer_last_update
                            .insert(network_name.clone(), SystemTime::now());
                    }
                    GlobalCtxEvent::PeerConnRemoved(..) => {
                        tracing::info!(?e, "clear no conn peer from foreign network manager");
                        data.clear_no_conn_peer(&network_name).await;
                    }
                    GlobalCtxEvent::PeerAdded(_) => {
                        tracing::info!(?e, "add peer to foreign network manager");
                        data.network_peer_last_update
                            .insert(network_name.clone(), SystemTime::now());
                    }
                    _ => continue,
                }
            }
            // if lagged or recv done just remove the network
            tracing::error!("global event handler at foreign network manager exit");
            data.remove_network(&network_name);
        });
    }

    pub async fn list_foreign_networks(&self) -> ListForeignNetworkResponse {
        let mut ret = ListForeignNetworkResponse::default();
        let networks = self
            .data
            .network_peer_maps
            .iter()
            .map(|v| v.key().clone())
            .collect::<Vec<_>>();

        for network_name in networks {
            let Some(item) = self
                .data
                .network_peer_maps
                .get(&network_name)
                .map(|v| v.clone())
            else {
                continue;
            };

            let mut entry = ForeignNetworkEntryPb {
                network_secret_digest: item
                    .network
                    .network_secret_digest
                    .unwrap_or_default()
                    .to_vec(),
                ..Default::default()
            };
            for peer in item.peer_map.list_peers().await {
                let mut peer_info = PeerInfo::default();
                peer_info.peer_id = peer;
                peer_info.conns = item.peer_map.list_peer_conns(peer).await.unwrap_or(vec![]);
                entry.peers.push(peer_info);
            }

            ret.foreign_networks.insert(network_name, entry);
        }
        ret
    }

    pub fn get_foreign_network_last_update(&self, network_name: &str) -> Option<SystemTime> {
        self.data
            .network_peer_last_update
            .get(network_name)
            .map(|v| v.clone())
    }

    pub async fn send_msg_to_peer(
        &self,
        network_name: &str,
        dst_peer_id: PeerId,
        msg: ZCPacket,
    ) -> Result<(), Error> {
        if let Some(entry) = self.data.get_network_entry(network_name) {
            entry
                .peer_map
                .send_msg(msg, dst_peer_id, NextHopPolicy::LeastHop)
                .await
        } else {
            Err(Error::RouteError(Some("network not found".to_string())))
        }
    }
}

impl Drop for ForeignNetworkManager {
    fn drop(&mut self) {
        self.data.peer_network_map.clear();
        self.data.network_peer_maps.clear();
    }
}
