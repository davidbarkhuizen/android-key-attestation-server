#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

use rocket_contrib::json::Json;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey {
    subject: String
}

#[post("/register", format="application/json", data = "<key>")]
fn register(key: Json<PublicKey>) -> String {
    //println!("{0}", key.subject)
    format!("{}", &key.subject)
}

#[get("/")]
fn index() -> &'static str {
    "indrajala fluid server"
}

fn main() {
    rocket::ignite().mount("/", routes![index]).launch();
}
