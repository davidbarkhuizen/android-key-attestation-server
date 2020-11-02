pub mod device {

    use crate::model::keys::keys::PublicKey;
    use rocket_contrib::json::Json;
   
    #[post("/register_init", format="application/json", data = "<key>")]
    pub fn register_init(key: Json<PublicKey>) -> String {
        //println!("{0}", key.subject)
        format!("{}", &key.subject)
    }
}