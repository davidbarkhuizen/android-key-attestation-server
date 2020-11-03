pub mod device {
    
    use crate::model::keys::keys::PublicKey;
    use rocket_contrib::json::Json;

    use rand::Rng;

    //let s: &'static str = "hello world";

    #[post("/register_init", format="application/json", data = "<key>")]
    pub fn register_init(key: Json<PublicKey>) -> String {

        let random_bytes = rand::thread_rng().gen::<[u8; 8]>();

        //println!("{0}", key.subject)
        format!("{:x?}", random_bytes)
    }
}