/* ---------------- PAGE SWITCH ENGINE ---------------- */
function showPage(id) {
  document.querySelectorAll(".page").forEach(p => {
    p.style.display = "none";
    p.classList.remove("active");
  });

  const page = document.getElementById(id);
  if (page) {
    page.style.display = "block";
    page.classList.add("active");
  }
}

/* ---------------- SQL INJECTION ---------------- */
function runSQL() {
  let u = document.getElementById("sqlUser").value;
  let p = document.getElementById("sqlPass").value;

  document.getElementById("sqlOutput").innerText =
`SELECT * FROM users
WHERE username='${u}' AND password='${p}';`;
}

/* ---------------- XSS ---------------- */
function renderXSS() {
  let ip = document.getElementById("xssInput").value;
  if (ip.includes("<script>")) {
    document.getElementById("xssOut").innerHTML =
      "<span style='color:red'>⚠ Script executed (simulated)</span>";
  } else {
    document.getElementById("xssOut").innerText = ip;
  }
}

/* ---------------- PERFECT BRUTE FORCE ENGINE ---------------- */

let bruteTimer = null;

function detectCharset(password) {
  let set = "";

  if (/[a-z]/.test(password)) set += "abcdefghijklmnopqrstuvwxyz";
  if (/[A-Z]/.test(password)) set += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (/[0-9]/.test(password)) set += "0123456789";
  if (/[^a-zA-Z0-9]/.test(password)) set += "!@#$%^&*()_+{}[]<>?/=-";

  if (set === "") set = "abcdefghijklmnopqrstuvwxyz0123456789";

  return set;
}

function generateAttempt(index, length, charset) {
  let base = charset.length;
  let result = new Array(length);

  for (let i = length - 1; i >= 0; i--) {
    result[i] = charset[index % base];
    index = Math.floor(index / base);
  }
  return result.join("");
}

function startBrute() {
  stopBrute();

  const target = document.getElementById("brutePassword").value.trim();
  if (!target) return alert("Enter password!");

  const charset = detectCharset(target);
  const length = target.length;
  const total = Math.pow(charset.length, length);

  let count = 0;
  let start = Date.now();

  const attemptBox = document.getElementById("bruteAttempt");
  const fill = document.getElementById("bruteProgressFill");
  const text = document.getElementById("bruteProgressText");
  const log = document.getElementById("bruteLog");

  log.innerText =
`✔ Charset: ${charset}
✔ Length: ${length}
✔ Total: ${total}`;

  bruteTimer = setInterval(() => {
    const attempt = generateAttempt(count, length, charset);
    attemptBox.innerText = attempt;

    if (attempt === target) {
      clearInterval(bruteTimer);

      let time = ((Date.now() - start)/1000).toFixed(2);
      log.innerText =
`🎉 CRACKED!
Password: ${attempt}
Attempts: ${count}
Time: ${time}s`;

      alert("Password Cracked: " + attempt);
      return;
    }

    let progress = ((count / total) * 100).toFixed(2);
    fill.style.width = progress + "%";
    text.innerText = progress + "%";

    count++;

    if (count >= total) {
      clearInterval(bruteTimer);
      log.innerText = "❌ Not found.";
    }
  }, 1);
}

function stopBrute() {
  if (bruteTimer) clearInterval(bruteTimer);
  bruteTimer = null;
  document.getElementById("bruteLog").innerText = "Stopped.";
}
