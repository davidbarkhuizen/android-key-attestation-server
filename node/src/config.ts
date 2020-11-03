export interface IConfigurationData {
    port: string;
}

export const configure = (): IConfigurationData => ({
    port: process.env.FLUID_SERVER_PORT
});