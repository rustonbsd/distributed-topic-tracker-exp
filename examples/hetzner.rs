use hcloud::apis::configuration::Configuration;
use hcloud::apis;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    
    let ssh_key = create_ssh_key().await?;
    println!("created ssh key: {}", ssh_key.name);
   
    let ssh_keys = list_ssh_keys().await?;
    println!("ssh keys: {:?}", ssh_keys.iter().map(|k| k.name.clone()).collect::<Vec<_>>());

    println!("server-types: {:?}", list_server_types().await?.iter().map(|k| k.name.clone()).collect::<Vec<_>>());
    println!("datacenters: {:?}", list_datacenters().await?.iter().map(|k| k.name.clone()).collect::<Vec<_>>());

    delete_ssh_key(ssh_key.clone()).await?;
    println!("deleted ssh key: {}", ssh_key.name);

    let ssh_keys = list_ssh_keys().await?;
    println!("ssh keys: {:?}", ssh_keys.iter().map(|k| k.name.clone()).collect::<Vec<_>>());

    Ok(())
}

async fn list_server_types() -> anyhow::Result<Vec<hcloud::models::ServerType>> {
    let server_types = apis::server_types_api::list_server_types(&get_config(), hcloud::apis::server_types_api::ListServerTypesParams::default()).await?;
    Ok(server_types.server_types)
}

async fn list_datacenters() -> anyhow::Result<Vec<hcloud::models::Datacenter>> {
    let datacenters = apis::datacenters_api::list_datacenters(&get_config(), hcloud::apis::datacenters_api::ListDatacentersParams::default()).await?;
    Ok(datacenters.datacenters)
}

async fn create_server(ssh_key: hcloud::models::SshKey,server_params: hcloud::models::CreateServerRequest) -> anyhow::Result<hcloud::models::Server> {
    let mut create_server_params = apis::servers_api::CreateServerParams::default();
    create_server_params.create_server_request = Some(server_params);
    let server_res = apis::servers_api::create_server(&get_config(), create_server_params).await?;
    Ok(*server_res.server)
}

fn get_config() -> Configuration {
    let mut config = hcloud::apis::configuration::Configuration::default();
    let api_key = std::env::var("HCLOUD_API_TOKEN").expect("HCLOUD_API_TOKEN not set");
    config.bearer_access_token = Some(api_key.to_string());
    config
}

async fn list_servers() -> anyhow::Result<Vec<hcloud::models::Server>> {
    let servers = apis::servers_api::list_servers(&get_config(), hcloud::apis::servers_api::ListServersParams::default()).await?;
    Ok(servers.servers)
}

async fn create_ssh_key() -> anyhow::Result<hcloud::models::SshKey> {
    let ssh_key = ssh_key::PrivateKey::random(&mut rand::thread_rng(), ssh_key::Algorithm::default())?;
    let mut ssh_key_params = apis::ssh_keys_api::CreateSshKeyParams::default();
    ssh_key_params.create_ssh_key_request = Some(hcloud::models::CreateSshKeyRequest {
        name:"test".to_string(),
        public_key: ssh_key.public_key().to_openssh()?, 
        labels: None 
    });
    let ssh_res = apis::ssh_keys_api::create_ssh_key(&get_config(), ssh_key_params).await?;
    Ok(*ssh_res.ssh_key)
}

async fn list_ssh_keys() -> anyhow::Result<Vec<hcloud::models::SshKey>> {
    let ssh_keys = apis::ssh_keys_api::list_ssh_keys(&get_config(), hcloud::apis::ssh_keys_api::ListSshKeysParams::default()).await?;
    Ok(ssh_keys.ssh_keys)
}

async fn delete_ssh_key(ssh_key: hcloud::models::SshKey) -> anyhow::Result<()> {
    let mut delete_ssh_key_params = apis::ssh_keys_api::DeleteSshKeyParams::default();
    delete_ssh_key_params.id = ssh_key.id;
    apis::ssh_keys_api::delete_ssh_key(&get_config(), delete_ssh_key_params).await?;
    Ok(())
}