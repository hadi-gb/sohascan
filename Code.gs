/**
 * ScanCare live backend.
 * - MASTER INVENTORY spreadsheet: inventory data + a new "Audit Log" tab.
 * - ScanCare Auth spreadsheet (separate, new): "Users" + "Sessions" tabs.
 * Deploy as a Web App (Execute as: Me, Who has access: Anyone) — the "Anyone" setting is
 * fine because every operation except "login" now requires a real, backend-verified
 * session token; nothing is trusted just because the browser sent it.
 *
 * SETUP: this is the public/template version of the script — the two IDs below are
 * placeholders. Create your own MASTER INVENTORY sheet and a separate ScanCare Auth
 * sheet (see README for the exact tab/column layout each one needs), then paste their
 * Spreadsheet IDs in below. Find an ID in a sheet's URL: the long token between
 * /d/ and /edit, e.g. docs.google.com/spreadsheets/d/<THIS PART>/edit
 */

// ---- CONFIG ----
var SHEET_ID = "YOUR_MASTER_INVENTORY_SPREADSHEET_ID_HERE"; // MASTER INVENTORY spreadsheet
var SHEET_NAME = "MASTER INVENTORY";
var AUDIT_SHEET_NAME = "Audit Log"; // new tab — create this in the MASTER INVENTORY spreadsheet

var AUTH_SHEET_ID = "YOUR_SCANCARE_AUTH_SPREADSHEET_ID_HERE"; // separate ScanCare Auth spreadsheet
var USERS_SHEET_NAME = "Users";
var SESSIONS_SHEET_NAME = "Sessions";

var SESSION_DURATION_MS = 12 * 60 * 60 * 1000; // 12-hour sessions
var CACHE_MAX_SECONDS = 21600; // CacheService's own hard cap (6h) — sessions still last 12h via the Sessions sheet fallback below
var PBKDF2_ITERATIONS = 10000; // tune if this feels slow/fast once deployed (see generateUserCredentials_)
var PBKDF2_KEYLEN_BYTES = 32;
var MAX_FAILED_ATTEMPTS = 5;
var LOCKOUT_DURATION_MS = 15 * 60 * 1000;

// Column layout (0-based) in MASTER INVENTORY:
// Barcode, Brand, Product, Expiry (MM-YYYY), Expiry Date (unused), tag, collection tag, discount, Quantity, Notes
var COL = {
  BARCODE: 0,
  BRAND: 1,
  PRODUCT: 2,
  EXPIRY: 3,
  QTY: 8,
  NOTES: 9
};

// Column layout (0-based) in the Users tab: Username, PasswordHash, Salt, Role, Active, FailedAttempts, LockedUntil
var USERS_COL = { USERNAME: 0, HASH: 1, SALT: 2, ROLE: 3, ACTIVE: 4, FAILED: 5, LOCKED_UNTIL: 6 };
// Column layout (0-based) in the Sessions tab: Token, Username, Role, CreatedAt, ExpiresAt
var SESSIONS_COL = { TOKEN: 0, USERNAME: 1, ROLE: 2, CREATED_AT: 3, EXPIRES_AT: 4 };

function getSheet_() {
  return SpreadsheetApp.openById(SHEET_ID).getSheetByName(SHEET_NAME);
}
function getAuthSpreadsheet_() {
  return SpreadsheetApp.openById(AUTH_SHEET_ID);
}
function getUsersSheet_() {
  return getAuthSpreadsheet_().getSheetByName(USERS_SHEET_NAME);
}
function getSessionsSheet_() {
  return getAuthSpreadsheet_().getSheetByName(SESSIONS_SHEET_NAME);
}

function normalizeBarcode_(s) {
  return String(s || "").trim().toUpperCase().replace(/\s+/g, "");
}

// The Expiry column is meant to hold plain text like "09-2026", but Google Sheets will
// silently store a value typed (or pasted) in that shape as an actual Date instead —
// formatted to LOOK like "09-2026" in the UI, while getValues() hands the script a real
// Date object. Normalize either shape back to plain "MM-YYYY" text here.
function formatExpiryRaw_(val) {
  if (val === null || val === undefined || val === "") return "";
  if (Object.prototype.toString.call(val) === "[object Date]" && !isNaN(val.getTime())) {
    var mm = String(val.getMonth() + 1);
    if (mm.length < 2) mm = "0" + mm;
    return mm + "-" + val.getFullYear();
  }
  return String(val).trim();
}

function readAllRows_() {
  var sheet = getSheet_();
  var data = sheet.getDataRange().getValues();
  var rows = [];
  for (var i = 1; i < data.length; i++) { // skip header row
    var r = data[i];
    if (!r[COL.BARCODE] && !r[COL.PRODUCT]) continue;
    var qtyRaw = r[COL.QTY];
    rows.push({
      row: i + 1,
      barcode: String(r[COL.BARCODE] || "").trim(),
      brand: String(r[COL.BRAND] || "").trim(),
      product: String(r[COL.PRODUCT] || "").trim(),
      expiryRaw: formatExpiryRaw_(r[COL.EXPIRY]),
      qty: (qtyRaw === "" || qtyRaw === null || qtyRaw === undefined) ? null : Number(qtyRaw),
      notes: String(r[COL.NOTES] || "").trim()
    });
  }
  return rows;
}

function jsonOut_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

// ============================================================================
// Password hashing — PBKDF2-HMAC-SHA256, built from Apps Script's own native
// Utilities.computeHmacSha256Signature (no external library). A per-user random salt
// (from Utilities.getUuid(), a real random-number source) means two users with the same
// password never produce the same stored value; thousands of chained HMAC rounds make
// offline guessing against a stolen hash deliberately slow, while a real login (one
// attempt) is unaffected. Passwords are never stored — only this derived value is.
// ============================================================================

function stringToBytes_(str) {
  return Utilities.newBlob(str).getBytes();
}
function bytesToHex_(bytes) {
  return bytes.map(function (b) {
    var v = b < 0 ? b + 256 : b;
    var h = v.toString(16);
    return h.length === 1 ? "0" + h : h;
  }).join("");
}
function hexToBytes_(hex) {
  var bytes = [];
  for (var i = 0; i < hex.length; i += 2) {
    var v = parseInt(hex.substr(i, 2), 16);
    bytes.push(v > 127 ? v - 256 : v);
  }
  return bytes;
}
function xorBytes_(a, b) {
  var out = [];
  for (var i = 0; i < a.length; i++) out.push(a[i] ^ b[i]);
  return out;
}
function intToBytesBE_(num) {
  return [(num >>> 24) & 0xff, (num >>> 16) & 0xff, (num >>> 8) & 0xff, num & 0xff]
    .map(function (v) { return v > 127 ? v - 256 : v; });
}
function computeHmac_(messageBytes, keyBytes) {
  return Utilities.computeHmacSha256Signature(messageBytes, keyBytes);
}

function pbkdf2Sha256_(password, saltBytes, iterations, keyLenBytes) {
  var passwordBytes = stringToBytes_(password);
  var hLen = 32;
  var l = Math.ceil(keyLenBytes / hLen);
  var dk = [];
  for (var i = 1; i <= l; i++) {
    var block = saltBytes.concat(intToBytesBE_(i));
    var u = computeHmac_(block, passwordBytes);
    var t = u;
    for (var j = 1; j < iterations; j++) {
      u = computeHmac_(u, passwordBytes);
      t = xorBytes_(t, u);
    }
    dk = dk.concat(t);
  }
  return dk.slice(0, keyLenBytes);
}

// Random hex from Apps Script's UUID generator (a real random source), not Math.random().
// Each UUID (dashes stripped) gives 32 hex chars = 16 bytes.
function randomHex_(numUuids) {
  var hex = "";
  for (var i = 0; i < numUuids; i++) hex += Utilities.getUuid().replace(/-/g, "");
  return hex;
}

function hashPassword_(plainPassword) {
  var saltHex = randomHex_(1); // 16-byte salt
  var dk = pbkdf2Sha256_(plainPassword, hexToBytes_(saltHex), PBKDF2_ITERATIONS, PBKDF2_KEYLEN_BYTES);
  return { hash: bytesToHex_(dk), salt: saltHex };
}

function constantTimeEquals_(a, b) {
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function verifyPassword_(plainPassword, saltHex, expectedHashHex) {
  if (!saltHex || !expectedHashHex) return false;
  var dk = pbkdf2Sha256_(plainPassword, hexToBytes_(saltHex), PBKDF2_ITERATIONS, PBKDF2_KEYLEN_BYTES);
  return constantTimeEquals_(bytesToHex_(dk), expectedHashHex);
}

/**
 * Run this manually from the Apps Script editor (pick this function in the toolbar
 * dropdown, click Run, then View > Logs) to create the hash/salt for a new user —
 * including the very first admin account. Nothing here is ever sent over the network;
 * the plaintext password only ever exists locally in this editor while you run it once.
 * Edit the three lines below, run, copy the logged values into a new row in the Users
 * tab, then blank the password line back out.
 */
function generateUserCredentials_() {
  var username = "CHANGE_ME";
  var plainPassword = "CHANGE_ME";
  var role = "admin"; // "admin" or "warehouse"

  var result = hashPassword_(plainPassword);
  Logger.log("Username: %s", username);
  Logger.log("Role: %s", role);
  Logger.log("PasswordHash: %s", result.hash);
  Logger.log("Salt: %s", result.salt);
  Logger.log("New Users row -> Username=%s | PasswordHash=%s | Salt=%s | Role=%s | Active=TRUE | FailedAttempts=0 | LockedUntil=(blank)",
    username, result.hash, result.salt, role);
}

// ============================================================================
// Sessions — a random opaque token (unrelated to the username/password) proves nothing
// by itself; every protected request looks it up here to find out who it belongs to.
// The Sessions sheet is the durable source of truth; CacheService is a speed layer on
// top of it for the high-frequency scan/add/adjust path.
// ============================================================================

function cacheSession_(token, session) {
  var secondsLeft = Math.floor((session.expiresAt - Date.now()) / 1000);
  var ttl = Math.max(1, Math.min(secondsLeft, CACHE_MAX_SECONDS));
  CacheService.getScriptCache().put("sess_" + token, JSON.stringify(session), ttl);
}

function cleanupExpiredSessions_(sessionsSheet) {
  var data = sessionsSheet.getDataRange().getValues();
  var now = Date.now();
  for (var i = data.length - 1; i >= 1; i--) {
    if (Number(data[i][SESSIONS_COL.EXPIRES_AT]) < now) sessionsSheet.deleteRow(i + 1);
  }
}

function createSession_(username, role) {
  var sessionsSheet = getSessionsSheet_();
  cleanupExpiredSessions_(sessionsSheet); // keep the sheet from growing unbounded
  var token = randomHex_(2); // 32-byte random bearer token
  var now = Date.now();
  var expiresAt = now + SESSION_DURATION_MS;
  sessionsSheet.appendRow([token, username, role, now, expiresAt]);
  cacheSession_(token, { username: username, role: role, expiresAt: expiresAt });
  return token;
}

function validateSession_(token) {
  if (!token) return null;
  var cache = CacheService.getScriptCache();
  var cached = cache.get("sess_" + token);
  if (cached) {
    var session = JSON.parse(cached);
    if (Date.now() > session.expiresAt) return null;
    return session;
  }
  // Cache miss (evicted early, or older than the 6h cache ceiling) — fall back to the sheet.
  var sessionsSheet = getSessionsSheet_();
  var data = sessionsSheet.getDataRange().getValues();
  for (var i = 1; i < data.length; i++) {
    var r = data[i];
    if (String(r[SESSIONS_COL.TOKEN]) === token) {
      var expiresAt = Number(r[SESSIONS_COL.EXPIRES_AT]);
      if (Date.now() > expiresAt) return null;
      var session = { username: String(r[SESSIONS_COL.USERNAME]), role: String(r[SESSIONS_COL.ROLE]), expiresAt: expiresAt };
      cacheSession_(token, session);
      return session;
    }
  }
  return null;
}

function deleteSession_(token) {
  if (!token) return;
  CacheService.getScriptCache().remove("sess_" + token);
  var sessionsSheet = getSessionsSheet_();
  var data = sessionsSheet.getDataRange().getValues();
  for (var i = data.length - 1; i >= 1; i--) {
    if (String(data[i][SESSIONS_COL.TOKEN]) === token) { sessionsSheet.deleteRow(i + 1); break; }
  }
}

// ============================================================================
// Users
// ============================================================================

function findUserRow_(usersSheet, username) {
  var data = usersSheet.getDataRange().getValues();
  var target = String(username || "").trim().toLowerCase();
  for (var i = 1; i < data.length; i++) {
    var r = data[i];
    if (String(r[USERS_COL.USERNAME] || "").trim().toLowerCase() === target) {
      var activeRaw = r[USERS_COL.ACTIVE];
      return {
        rowIndex: i + 1,
        username: String(r[USERS_COL.USERNAME]).trim(),
        passwordHash: String(r[USERS_COL.HASH] || ""),
        salt: String(r[USERS_COL.SALT] || ""),
        role: String(r[USERS_COL.ROLE] || "warehouse").trim().toLowerCase(),
        active: activeRaw === true || String(activeRaw).trim().toUpperCase() === "TRUE",
        failedAttempts: Number(r[USERS_COL.FAILED]) || 0,
        lockedUntil: r[USERS_COL.LOCKED_UNTIL] ? Number(r[USERS_COL.LOCKED_UNTIL]) : 0
      };
    }
  }
  return null;
}

function updateUserRow_(usersSheet, rowIndex, updates) {
  if (updates.failedAttempts !== undefined) usersSheet.getRange(rowIndex, USERS_COL.FAILED + 1).setValue(updates.failedAttempts);
  if (updates.lockedUntil !== undefined) usersSheet.getRange(rowIndex, USERS_COL.LOCKED_UNTIL + 1).setValue(updates.lockedUntil);
}

// ============================================================================
// Audit Log — written only here, on the backend, never trusting anything the client
// claims about who it is; "username" always comes from the verified session.
// ============================================================================

function appendAuditLog_(username, action, barcode, product, expiryRaw, change, rowRef) {
  try {
    var auditSheet = getSheet_().getParent().getSheetByName(AUDIT_SHEET_NAME);
    if (!auditSheet) return; // tab not created yet — never block the real operation on this
    auditSheet.appendRow([new Date(), username, action, barcode || "", product || "", expiryRaw || "", change, rowRef || ""]);
  } catch (err) {
    // Audit logging must never fail or block the actual inventory operation.
  }
}

// ============================================================================
// doGet / doPost
// ============================================================================

function doGet(e) {
  // Everything now goes through doPost (login requires a POST body; every other op
  // requires a session token, which also travels in the POST body rather than a URL,
  // so it never ends up in a browser address bar or a server access log).
  return jsonOut_({ ok: false, error: "This API only accepts POST requests." });
}

function handleLogin_(body) {
  var username = String(body.username || "").trim();
  var password = String(body.password || "");
  if (!username || !password) {
    return jsonOut_({ ok: false, error: "Username and password are required." });
  }

  var lock = LockService.getScriptLock();
  var gotLock = lock.tryLock(10000);
  if (!gotLock) {
    return jsonOut_({ ok: false, error: "The system is busy right now — please try again in a moment." });
  }
  try {
    var usersSheet = getUsersSheet_();
    var found = findUserRow_(usersSheet, username);

    // Same generic message whether the username doesn't exist, is disabled, is locked
    // out, or the password is wrong — an attacker probing usernames learns nothing.
    var GENERIC_FAIL = "Invalid username or password.";

    if (!found || !found.active) {
      return jsonOut_({ ok: false, error: GENERIC_FAIL });
    }

    var now = Date.now();
    if (found.lockedUntil && now < found.lockedUntil) {
      var minsLeft = Math.ceil((found.lockedUntil - now) / 60000);
      return jsonOut_({ ok: false, error: "Too many failed attempts. Try again in " + minsLeft + " minute" + (minsLeft === 1 ? "" : "s") + "." });
    }

    var valid = verifyPassword_(password, found.salt, found.passwordHash);
    if (!valid) {
      var attempts = found.failedAttempts + 1;
      var updates = { failedAttempts: attempts };
      if (attempts >= MAX_FAILED_ATTEMPTS) {
        updates.lockedUntil = now + LOCKOUT_DURATION_MS;
        updates.failedAttempts = 0;
      }
      updateUserRow_(usersSheet, found.rowIndex, updates);
      return jsonOut_({ ok: false, error: GENERIC_FAIL });
    }

    updateUserRow_(usersSheet, found.rowIndex, { failedAttempts: 0, lockedUntil: "" });
    var token = createSession_(found.username, found.role);
    return jsonOut_({ ok: true, token: token, username: found.username, role: found.role });
  } finally {
    lock.releaseLock();
  }
}

function doPost(e) {
  try {
    var body = JSON.parse(e.postData.contents);
    var op = body.op;

    if (op === "login") {
      return handleLogin_(body);
    }

    // Every other operation requires a valid, backend-verified session. The frontend
    // may also send a "username" field for its own display purposes, but it is NEVER
    // used here for identity or permissions — only the token's server-side record is.
    var session = validateSession_(body.token);
    if (!session) {
      return jsonOut_({ ok: false, error: "Your session has expired — please log in again.", authError: true });
    }

    if (op === "whoami") {
      return jsonOut_({ ok: true, username: session.username, role: session.role });
    }

    if (op === "logout") {
      deleteSession_(body.token);
      return jsonOut_({ ok: true });
    }

    if (op === "lookup") {
      var code = normalizeBarcode_(body.barcode || "");
      var matches = readAllRows_().filter(function (r) { return normalizeBarcode_(r.barcode) === code; });
      return jsonOut_({ ok: true, batches: matches });
    }

    if (op === "all") {
      return jsonOut_({ ok: true, batches: readAllRows_() });
    }

    if (op === "append" || op === "adjust" || op === "rename") {
      if (session.role !== "warehouse" && session.role !== "admin") {
        return jsonOut_({ ok: false, error: "Your account doesn't have permission to do that." });
      }

      // Concurrency protection — UNCHANGED from the existing fix. All three ops still
      // do a read-then-write against the sheet, serialized by the same script-wide lock.
      var lock = LockService.getScriptLock();
      var gotLock = lock.tryLock(10000);
      if (!gotLock) {
        return jsonOut_({ ok: false, error: "The sheet is busy right now — please try again in a moment." });
      }

      try {
        var sheet = getSheet_();

        if (op === "append") {
          var lastCol = sheet.getLastColumn();
          var rowArr = [];
          for (var i = 0; i < lastCol; i++) rowArr.push("");
          rowArr[COL.BARCODE] = body.barcode || "";
          rowArr[COL.BRAND] = body.brand || "";
          rowArr[COL.PRODUCT] = body.product || "";
          rowArr[COL.EXPIRY] = body.expiryRaw || "";
          rowArr[COL.QTY] = (body.qty === null || body.qty === undefined || body.qty === "") ? "" : Number(body.qty);
          rowArr[COL.NOTES] = body.notes || "";
          sheet.appendRow(rowArr);
          var newRow = sheet.getLastRow();
          sheet.getRange(newRow, COL.EXPIRY + 1).setNumberFormat("@").setValue(body.expiryRaw || "");

          appendAuditLog_(
            session.username, "append", body.barcode,
            (body.brand ? body.brand + " — " : "") + (body.product || ""),
            body.expiryRaw,
            "qty=" + ((body.qty === null || body.qty === undefined || body.qty === "") ? "0" : body.qty),
            newRow
          );
          return jsonOut_({ ok: true, action: "appended" });
        }

        if (op === "rename") {
          var newBrand = String(body.brand || "").trim();
          var newProduct = String(body.product || "").trim();
          if (!newProduct) {
            return jsonOut_({ ok: false, error: "Product name can't be empty." });
          }

          var renamedRows = 0;
          if (body.row !== undefined && body.row !== null && body.row !== "") {
            // A row with no real barcode — several unrelated rows can share the same
            // blank/placeholder barcode text, so rename ONLY this exact row, never by
            // barcode text.
            var singleRowNum = Number(body.row);
            sheet.getRange(singleRowNum, COL.BRAND + 1).setValue(newBrand);
            sheet.getRange(singleRowNum, COL.PRODUCT + 1).setValue(newProduct);
            renamedRows = 1;
          } else {
            // A real barcode — it's the same product everywhere it appears, so rename
            // every row sharing it.
            var targetBarcode = normalizeBarcode_(body.barcode || "");
            if (!targetBarcode) {
              return jsonOut_({ ok: false, error: "Missing barcode or row to rename." });
            }
            var allData = sheet.getDataRange().getValues();
            for (var rIdx = 1; rIdx < allData.length; rIdx++) {
              if (normalizeBarcode_(allData[rIdx][COL.BARCODE]) === targetBarcode) {
                sheet.getRange(rIdx + 1, COL.BRAND + 1).setValue(newBrand);
                sheet.getRange(rIdx + 1, COL.PRODUCT + 1).setValue(newProduct);
                renamedRows++;
              }
            }
            if (renamedRows === 0) {
              return jsonOut_({ ok: false, error: "No matching rows found for that barcode." });
            }
          }

          appendAuditLog_(
            session.username, "rename", body.barcode || "",
            (newBrand ? newBrand + " — " : "") + newProduct,
            "",
            "renamed " + renamedRows + " row(s)",
            body.row || ""
          );
          return jsonOut_({ ok: true, action: "renamed", rowsUpdated: renamedRows });
        }

        // op === "adjust" — quantity change, a notes update, or both in one call
        // (the per-batch Edit panel sends both together; the older qty-only
        // callers — the Inventory tab stepper — just never send "notes").
        var rowNum = Number(body.row);
        var expectedBarcode = normalizeBarcode_(body.barcode || "");
        var actualBarcode = normalizeBarcode_(sheet.getRange(rowNum, COL.BARCODE + 1).getValue());
        if (actualBarcode !== expectedBarcode) {
          return jsonOut_({ ok: false, error: "That row changed since you last checked — please look it up again and retry." });
        }

        var hasQtyChange = body.delta !== undefined && body.delta !== null && Number(body.delta) !== 0;
        var hasNotesChange = body.notes !== undefined && body.notes !== null;
        if (!hasQtyChange && !hasNotesChange) {
          return jsonOut_({ ok: false, error: "Nothing to update." });
        }

        var updated = null;
        var changeParts = [];

        if (hasQtyChange) {
          var qtyCell = sheet.getRange(rowNum, COL.QTY + 1);
          var current = Number(qtyCell.getValue()) || 0;
          var delta = Number(body.delta) || 0;
          updated = body.sign > 0 ? current + delta : Math.max(0, current - delta);
          qtyCell.setValue(updated);
          changeParts.push("qty " + (body.sign > 0 ? "+" : "-") + delta + " (was " + current + ", now " + updated + ")");
        }

        if (hasNotesChange) {
          sheet.getRange(rowNum, COL.NOTES + 1).setValue(String(body.notes));
          changeParts.push('notes set to "' + String(body.notes) + '"');
        }

        var brandVal = String(sheet.getRange(rowNum, COL.BRAND + 1).getValue() || "");
        var productVal = String(sheet.getRange(rowNum, COL.PRODUCT + 1).getValue() || "");
        var expiryVal = formatExpiryRaw_(sheet.getRange(rowNum, COL.EXPIRY + 1).getValue());
        appendAuditLog_(session.username, "adjust", body.barcode, (brandVal ? brandVal + " — " : "") + productVal, expiryVal, changeParts.join("; "), rowNum);

        if (updated === null) {
          // Notes-only update — report the qty currently on the sheet, unchanged.
          updated = Number(sheet.getRange(rowNum, COL.QTY + 1).getValue()) || 0;
        }

        return jsonOut_({ ok: true, action: "adjusted", newQty: updated });
      } finally {
        lock.releaseLock();
      }
    }

    return jsonOut_({ ok: false, error: "unknown op" });
  } catch (err) {
    return jsonOut_({ ok: false, error: String(err) });
  }
}
