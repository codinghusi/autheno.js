
function toBase64(str: string) {
    return Buffer.from(str).toString("base64");
}

// TODO: improve it (collisions possible)
export function * idGenerator() {
    let index = 0;
    while (true) {
        index++;
        const now = Date.now();
        const first = toBase64(now.toString(16));
        const second = toBase64(index.toString(16));
        const id = `${first}.${second}`;
        yield id;
    }
}