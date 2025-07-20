
use futures::future::join_all;
use mainline::{Dht, Id, MutableItem, SigningKey};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    
    let mut futures = vec![];
    for i in 0..10 {
        futures.push(tokio::spawn({
            let signing_key = signing_key.clone();
            let i = i.to_string();
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(rand::random::<u64>() % 3000)).await;
                let dht = Dht::client().unwrap();
                let res = write_record(
                    dht.clone(),
                    signing_key,
                    format!("{}", i).as_bytes().to_vec(),
                    Some(b"123"),
                );
                println!("res-{} is error={} data={}", i, res.is_err(),format!("{}", i));
            }
        }));
    }

    join_all(futures).await;

    loop {
        let dht = Dht::client()?;
        let records = dht.get_mutable(signing_key.verifying_key().as_bytes(), Some(b"123"),None).collect::<Vec<_>>();
        println!("records: {:?}", records.iter().map(|r|r.value()).collect::<Vec<_>>());
    }
}

fn write_record(dht: Dht, signing_key: SigningKey, record: Vec<u8>,salt: Option<&[u8]>) -> anyhow::Result<Id> {
    let item = if let Some(mut_item)  = dht.get_mutable_most_recent(signing_key.verifying_key().as_bytes(), None) {
        MutableItem::new(signing_key, &record, mut_item.seq() + 1, salt)
    } else {
        MutableItem::new(signing_key, &record, 0, salt)
    };

    let id = dht.put_mutable(item.clone(), Some(item.seq()))?;


    Ok(id)
}
