#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

mod controllers;
mod model;

use crate::device::device::static_rocket_route_info_for_register_init;
use controllers::device;

use rocket_contrib::json::Json;
use serde::Deserialize;
use serde::Serialize;

#[get("/")]
fn index() -> &'static str {
    "indrajala fluid server"
}

fn main() {
    rocket::ignite().mount("/", routes![index, register_init]).launch();
}
