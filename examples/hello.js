const words = "the quick brown fox jumps over the lazy dog".split(" ");
console.log(JSON.stringify({ count: words.length, longest: words.reduce((a, b) => (b.length > a.length ? b : a)) }));
