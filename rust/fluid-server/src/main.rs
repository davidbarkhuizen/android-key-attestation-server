#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

extern crate rand;

mod controllers;
mod model;

use crate::controllers::device::device::static_rocket_route_info_for_register_init;
use rocket_contrib::json::Json;
use serde::Deserialize;
use serde::Serialize;

use rand::Rng;

#[get("/")]
fn index() -> &'static str {
    "indrajala fluid server"
}

fn main() {

    rocket::ignite()
        .mount("/", routes![index])
        .mount("/device", routes![register_init])
        .launch();
}
