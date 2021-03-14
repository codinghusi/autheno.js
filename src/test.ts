

(async () => {
    const foo = Promise.resolve("bar");
    console.log(await foo);
    console.log(await foo);

    setTimeout(() => foo.then(console.log), 1000);
})()