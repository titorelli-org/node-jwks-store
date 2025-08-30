import {dirname} from "node:path";
import {access, constants, readFile, writeFile} from "node:fs/promises";
import {mkdirpSync} from "mkdirp";
import {JWK} from "jose";

export class JwksStore {
    constructor(private readonly filename: string) {
        mkdirpSync(dirname(filename));
    }

    public async get() {
        if (await this.isFileExists()) {
            return this.readFromFile();
        }

        const data = await this.generate();

        await this.writeToFile(data);

        return data;
    }

    public async selectForVerify(needleAlg: string, needleKid: string): Promise<JWK | undefined> {
        const { keys } = await this.get()

        for (const [i, { alg, kid }] of Object.entries(keys)) {
            if (needleAlg === alg && needleKid === kid) {
                return keys[i]
            }
        }
    }

    private async isFileExists() {
        try {
            await access(this.filename, constants.R_OK | constants.W_OK);

            return true;
        } catch (_err) {
            const err = _err as Error;

            if (!err.message.includes("no such file or directory")) {
                console.error("Error when checking file access rights:", err);
            }

            return false;
        }
    }

    private async readFromFile() {
        if (!(await this.isFileExists())) {
            throw new Error("Cannot read file: " + this.filename);
        }

        const text = await readFile(this.filename, {encoding: "utf-8"});
        const data = JSON.parse(text) as { keys: JWK[] };

        return data;
    }

    private async writeToFile(data: { keys: JWK[] }) {
        const text = JSON.stringify(data, null, 2);

        await writeFile(this.filename, text, {encoding: "utf-8"});
    }

    private async generate() {
        const {generateKeyPair, exportJWK} = await import("jose");

        const rsaSigningKey = await generateKeyPair("RS256", {extractable: true});
        const ecSigningKey = await generateKeyPair("ES256", {extractable: true});

        // const rsaEncryptionKey = await generateKeyPair("RSA-OAEP", {
        //   extractable: true,
        // });
        // const ecEncryptionKey = await generateKeyPair("ECDH-ES", {
        //   extractable: true,
        // });

        const [rsaSigJwk, ecSigJwk /*, rsaEncJwk, ecEncJwk*/] = await Promise.all([
            exportJWK(rsaSigningKey.privateKey),
            exportJWK(ecSigningKey.privateKey),
            // exportJWK(rsaEncryptionKey.privateKey),
            // exportJWK(ecEncryptionKey.privateKey),
        ]);

        rsaSigJwk.kid = "sig-rs-0";
        rsaSigJwk.alg = "RS256";
        rsaSigJwk.use = "sig";

        ecSigJwk.kid = "sig-ec-0";
        ecSigJwk.alg = "ES256";
        ecSigJwk.use = "sig";

        // rsaEncJwk.kid = "enc-rs-0";
        // rsaEncJwk.alg = "RSA-OAEP";
        // rsaEncJwk.use = "enc";

        // ecEncJwk.kid = "enc-ec-0";
        // ecEncJwk.alg = "ECDH-ES";
        // ecEncJwk.use = "enc";

        return {
            keys: [rsaSigJwk, ecSigJwk],
        };
    }
}
