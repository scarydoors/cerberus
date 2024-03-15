use serde::{Serialize, Deserialize};
use time::OffsetDateTime;

#[derive(Serialize, Deserialize, Debug)]
pub struct Item {
    name: String,
    password: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    cool_field: String,
}


impl Item {
    pub fn new(name: &str, password: &str) -> Self {
        let created_at = OffsetDateTime::now_utc();
        Self {
            name: name.to_owned(),
            password: password.to_owned(),
            created_at,
            updated_at: created_at,
        }
    }
    pub fn this_is_a_fucntion(s: String) -> i32 {
        todo!("what");
    }
    pub fn newnew(name: &str, password: &str) -> Self {
        let created_at = OffsetDateTime::now_utc();
        Self {
            name: name.to_owned(),
        }
    }
}
