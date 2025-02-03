use cerberus_store::item::{ItemData, ItemOverview};
use cerberus_store::Store;
use sqlx::SqlitePool;

use crate::Store;

use crate::database::MIGRATOR;

#[sqlx::test(migrator = "MIGRATOR")]
async fn can_store_and_retrieve_data(pool: SqlitePool) {
    let mut store = Store::from_pool(pool).unwrap();

    let password = String::from("mypassword");
    store.initialize_profile("User".to_owned(), &password).await.unwrap();

    let vault_name = String::from("Personal vault");
    let vault = store.create_vault("Personal vault".to_owned()).await.unwrap();
    {
        let name = String::from("My item");
        let site = String::from("https://my-item.com");
        let item_overview = ItemOverview::new(
            name.clone(),
            site.clone()
        );

        let secret = String::from("item-password");
        let item_data = ItemData::new(secret.clone());

        let item = vault.create_item(item_overview, item_data).await.unwrap();

        let item_overview = item.overview().unwrap();
        let item_data = item.data().unwrap();

        assert_eq!(item_overview.site(), site);
        assert_eq!(item_overview.name(), name);
        assert_eq!(item_data.secret(), secret);
    }

    store.lock().unwrap();
    let vaults = store.list_vaults().await.unwrap();
    assert_eq!(vaults.len(), 1);

    let vault = vaults.get(1).unwrap();
    let vault_id = vault.id();
    store.get_vault(vault.id()).await.expect_err("The store is locked");

    store.unlock(&password).await.unwrap();
    let vault = store.get_vault(vault.id()).await.unwrap();

}
