pub mod keys {

    use serde::Deserialize;
    use serde::Serialize;

    #[derive(Serialize, Deserialize, Debug)]
    pub struct PublicKey {
        pub subject: String
    }
}