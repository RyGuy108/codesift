function f(a) {
  var x = 1;
  if (a == "1") { debugger; }
  console.log("value == " + a);
  for (const u of a) {
    const r = await fetch(u);
  }
  try { g(); } catch (e) {}
  return x != null;
}
