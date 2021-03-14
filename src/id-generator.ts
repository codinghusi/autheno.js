
// TODO: improve it (collisions possible)
export function * idGenerator() {
    let index = 0;
    while (true) {
        index++;
        const now = Date.now();
        const first = btoa(now.toString(16));
        const second = btoa(index.toString(16));
        const id = `${first}.${second}`;
        yield id;
    }
}