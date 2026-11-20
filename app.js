import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getFirestore, doc, setDoc, getDoc, collection, query, where, onSnapshot,
  addDoc, serverTimestamp, getDocs, limit, updateDoc, arrayUnion
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { firebaseConfig } from "./firebase-config.js";

const $ = id => document.getElementById(id);
const app = initializeApp(firebaseConfig), auth = getAuth(app), db = getFirestore(app);
const encoder = new TextEncoder(), decoder = new TextDecoder();
let authMode = "register", currentUser = null, myProfile = null, privateKey = null;
let activeConversation = null, stopMessages = null, stopConversations = null, stopIncoming = null;
let knownMessages = new Set(), localContacts = [], conversationCache = new Map(), incomingInitialized = false;
const contactsKey = uid => `securechat-contacts-${uid}`;

function toast(message) {
  $("toast").textContent = message;
  $("toast").classList.remove("hidden");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => $("toast").classList.add("hidden"), 3200);
}
function show(id, yes = true) { $(id).classList.toggle("hidden", !yes); }
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  }[c]));
}
function makeCode() {
  return "SC-" + crypto.getRandomValues(new Uint8Array(3))
    .reduce((s, b) => s + b.toString(16).padStart(2, "0"), "").toUpperCase();
}
function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function unb64(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
function keyStoreName(uid) { return "securechat-rsa-private-" + uid; }
function sortedParticipants(ids) { return [...new Set(ids)].sort(); }
function conversationKey(ids) { return sortedParticipants(ids).join("_"); }
function displayName(conversation) {
  if (conversation.name) return conversation.name;
  const others = (conversation.memberProfiles || []).filter(p => p.uid !== currentUser.uid);
  return others.map(p => p.name).join(", ") || "Saved messages";
}
function initials(name) { return (name || "U").trim().slice(0, 1).toUpperCase(); }

async function createKeys() {
  const pair = await crypto.subtle.generateKey(
    { name:"RSA-OAEP", modulusLength:3072, publicExponent:new Uint8Array([1,0,1]), hash:"SHA-256" },
    true, ["encrypt", "decrypt"]
  );
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const priv = await crypto.subtle.exportKey("jwk", pair.privateKey);
  localStorage.setItem(keyStoreName(currentUser.uid), JSON.stringify(priv));
  privateKey = pair.privateKey;
  return pub;
}
async function importPrivate() {
  const raw = localStorage.getItem(keyStoreName(currentUser.uid));
  if (!raw) return null;
  const jwk = JSON.parse(raw);
  return crypto.subtle.importKey("jwk", jwk, { name:"RSA-OAEP", hash:"SHA-256" }, false, ["decrypt"]);
}
async function ensureProfile(name = "") {
  const ref = doc(db, "users", currentUser.uid), snap = await getDoc(ref);
  let data = snap.exists() ? snap.data() : null;
  if (!data) {
    data = {
      uid: currentUser.uid, name: name || currentUser.email.split("@")[0],
      code: makeCode(), publicKey: null, createdAt: serverTimestamp()
    };
    await setDoc(ref, data);
  }
  myProfile = data;
  privateKey = await importPrivate();
  if (!privateKey || !data.publicKey) {
    const pub = await createKeys();
    await setDoc(ref, { publicKey: pub }, { merge:true });
    myProfile.publicKey = pub;
  }
  $("myName").textContent = data.name;
  $("myAvatar").textContent = initials(data.name);
  $("myCode").textContent = data.code;
  $("account").textContent = currentUser.email;
  localContacts = JSON.parse(localStorage.getItem(contactsKey(currentUser.uid)) || "[]");
  renderContacts();
}
function renderAuth() { show("authView", true); show("appView", false); show("account", false); }
async function enterApp(user, name = "") {
  currentUser = user;
  show("authView", false); show("appView", true); show("account", true);
  await ensureProfile(name);
  listenConversations();
  listenIncomingMessages();
  setupNotifications();
}
function authErrorText(error) {
  const code = error?.code || "";
  const messages = {
    "auth/operation-not-allowed": "Email/Password sign-in is disabled in Firebase. Firebase Console → Authentication → Sign-in method → Email/Password → Enable, then Save.",
    "auth/unauthorized-domain": "This website domain is not authorized. Firebase Console → Authentication → Settings → Authorized domains → Add your current hostname (for local testing add localhost).",
    "auth/invalid-api-key": "Firebase API key is invalid. Check firebase-config.js and confirm it belongs to project rsa-874d7.",
    "auth/network-request-failed": "Firebase could not be reached. Check your internet connection, browser extensions, and open the site over HTTPS or localhost.",
    "auth/email-already-in-use": "This email already has an account. Choose Sign in instead of Create account.",
    "auth/weak-password": "The password is too weak. Use at least 6 characters.",
    "auth/invalid-email": "Please enter a valid email address.",
    "auth/invalid-credential": "Email or password is incorrect. Check both and try again.",
    "auth/user-not-found": "No account was found for this email. Create an account first.",
    "auth/wrong-password": "The password is incorrect. Try again.",
    "auth/too-many-requests": "Too many attempts. Wait a little while before trying again."
  };
  return (messages[code] || error?.message || "Unknown Firebase Authentication error.")
    + (code ? ` [${code}]` : "");
}
$("authForm").addEventListener("submit", async event => {
  event.preventDefault();
  const email = $("email").value.trim(), password = $("password").value;
  const name = $("displayName").value.trim();
  const button = $("authSubmit");
  const errorBox = $("authError");
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
  button.disabled = true;
  const originalLabel = button.textContent;
  button.textContent = authMode === "register" ? "Creating account…" : "Signing in…";
  try {
    if (authMode === "register") {
      if (!name) throw Error("Please enter your display name.");
      sessionStorage.setItem("securechat-pending-name", name);
      await createUserWithEmailAndPassword(auth, email, password);
    } else {
      await signInWithEmailAndPassword(auth, email, password);
    }
  } catch (error) {
    sessionStorage.removeItem("securechat-pending-name");
    errorBox.textContent = authErrorText(error);
    errorBox.classList.remove("hidden");
    toast(error?.code || error?.message || "Authentication failed");
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
  }
});
document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", () => {
  authMode = button.dataset.tab;
  if ($("authError")) { $("authError").textContent = ""; $("authError").classList.add("hidden"); }
  document.querySelectorAll(".tab").forEach(tab => tab.classList.toggle("active", tab === button));
  $("nameLabel").classList.toggle("hidden", authMode === "login");
  $("displayName").classList.toggle("hidden", authMode === "login");
  $("displayName").required = authMode === "register";
  $("authSubmit").textContent = authMode === "register" ? "Create account" : "Sign in";
}));
onAuthStateChanged(auth, async user => {
  if (user) {
    try {
      const pendingName = sessionStorage.getItem("securechat-pending-name") || "";
      sessionStorage.removeItem("securechat-pending-name");
      await enterApp(user, pendingName);
    } catch (error) { toast("Setup error: " + error.message); }
  } else {
    currentUser = null;
    if (stopConversations) stopConversations();
    if (stopMessages) stopMessages();
    if (stopIncoming) stopIncoming();
    incomingInitialized = false;
    renderAuth();
  }
});
$("logoutBtn").onclick = () => signOut(auth);
$("copyId").onclick = async () => {
  try { await navigator.clipboard.writeText(myProfile.code); toast("Your ID was copied."); }
  catch { toast("Copy is not available in this browser."); }
};

function saveContact(profile) {
  if (!profile?.uid || profile.uid === currentUser.uid) return;
  const existing = localContacts.findIndex(c => c.uid === profile.uid);
  if (existing >= 0) localContacts[existing] = { uid:profile.uid, name:profile.name, code:profile.code, publicKey:profile.publicKey };
  else localContacts.unshift({ uid:profile.uid, name:profile.name, code:profile.code, publicKey:profile.publicKey });
  localContacts = localContacts.slice(0, 100);
  localStorage.setItem(contactsKey(currentUser.uid), JSON.stringify(localContacts));
  renderContacts();
}
function renderContacts() {
  const target = $("savedContacts");
  if (!target) return;
  target.innerHTML = "";
  if (!localContacts.length) {
    target.innerHTML = '<p class="muted small">Contacts you add by ID will appear here on this device.</p>';
    return;
  }
  for (const contact of localContacts) {
    const item = document.createElement("button");
    item.className = "contact-item";
    item.innerHTML = `<span class="avatar mini">${escapeHtml(initials(contact.name))}</span><span><b>${escapeHtml(contact.name)}</b><small>${escapeHtml(contact.code)}</small></span>`;
    item.onclick = () => createOrOpenDirect(contact);
    target.append(item);
  }
}
async function findUserByCode(code) {
  const q = query(collection(db, "users"), where("code", "==", code.toUpperCase()), limit(1));
  const result = await getDocs(q);
  if (result.empty) throw Error(`No account found for ID ${code}.`);
  const profile = result.docs[0].data();
  if (profile.uid === currentUser.uid) throw Error("You cannot add your own ID.");
  if (!profile.publicKey) throw Error("This user has not created encryption keys yet.");
  return profile;
}
async function getMemberProfiles(ids) {
  const profiles = [];
  for (const uid of ids) {
    if (uid === currentUser.uid) profiles.push({ uid, name:myProfile.name, code:myProfile.code, publicKey:myProfile.publicKey });
    else {
      const snap = await getDoc(doc(db, "users", uid));
      if (!snap.exists()) throw Error("A group member profile is no longer available.");
      const p = snap.data();
      if (!p.publicKey) throw Error(`${p.name || "A member"} has no encryption key yet.`);
      profiles.push({ uid:p.uid, name:p.name, code:p.code, publicKey:p.publicKey });
      saveContact(p);
    }
  }
  return profiles;
}
async function createConversation(memberProfiles, groupName = "") {
  const ids = sortedParticipants(memberProfiles.map(p => p.uid));
  if (ids.length < 2) throw Error("Add at least one other person.");
  if (ids.length > 20) throw Error("Groups are limited to 20 members in this version.");
  const id = conversationKey(ids);
  const ref = doc(db, "conversations", id), existing = await getDoc(ref);
  if (!existing.exists()) {
    await setDoc(ref, {
      participants: ids, memberProfiles,
      name: groupName.trim() || (ids.length > 2 ? "Group chat" : ""),
      createdBy: currentUser.uid, createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(), lastMessage: ""
    });
  }
  const conversation = (await getDoc(ref)).data();
  conversation.id = id;
  conversationCache.set(id, conversation);
  openConversation(conversation);
  return conversation;
}
async function createOrOpenDirect(profile) {
  const members = await getMemberProfiles([currentUser.uid, profile.uid]);
  return createConversation(members);
}
$("newChatBtn").onclick = $("emptyNewChat").onclick = () => {
  $("memberIds").value = "";
  $("groupName").value = "";
  $("lookupResults").innerHTML = "";
  $("newChatDialog").showModal();
};
$("lookupMembersBtn").onclick = async () => {
  const codes = $("memberIds").value.split(/[\s,;]+/).map(s => s.trim().toUpperCase()).filter(Boolean);
  if (!codes.length) { toast("Enter at least one User ID."); return; }
  if (codes.length > 19) { toast("You can add up to 19 other members."); return; }
  const profiles = [], errors = [];
  for (const code of [...new Set(codes)]) {
    try { profiles.push(await findUserByCode(code)); }
    catch (error) { errors.push(`${code}: ${error.message}`); }
  }
  $("lookupResults").innerHTML = profiles.map(p =>
    `<div class="lookup-person"><span class="avatar mini">${escapeHtml(initials(p.name))}</span><span><b>${escapeHtml(p.name)}</b><small>${escapeHtml(p.code)}</small></span><span class="member-ok">Added</span></div>`
  ).join("") + (errors.length ? `<p class="lookup-errors">${escapeHtml(errors.join(" • "))}</p>` : "");
  $("lookupResults").dataset.memberUids = JSON.stringify(profiles.map(p => p.uid));
  if (profiles.length) toast(`${profiles.length} member${profiles.length > 1 ? "s" : ""} found.`);
};
$("createChatBtn").onclick = async () => {
  try {
    const ids = JSON.parse($("lookupResults").dataset.memberUids || "[]");
    if (!ids.length) throw Error("Find at least one valid User ID first.");
    const members = await getMemberProfiles([currentUser.uid, ...ids]);
    await createConversation(members, $("groupName").value);
    $("newChatDialog").close();
  } catch (error) { toast(error.message); }
};
function listenConversations() {
  if (stopConversations) stopConversations();
  const q = query(collection(db, "conversations"), where("participants", "array-contains", currentUser.uid));
  stopConversations = onSnapshot(q, snapshot => {
    const conversations = snapshot.docs.map(d => ({ id:d.id, ...d.data() }));
    conversations.sort((a,b) => (b.updatedAt?.toMillis?.() || 0) - (a.updatedAt?.toMillis?.() || 0));
    $("chatList").innerHTML = "";
    if (!conversations.length) {
      $("chatList").innerHTML = '<p class="muted small">No conversations yet. Start a chat using a User ID.</p>';
      return;
    }
    conversations.forEach(conversation => {
      conversationCache.set(conversation.id, conversation);
      const item = document.createElement("button");
      item.className = "chat-item" + (activeConversation?.id === conversation.id ? " active" : "");
      const count = conversation.participants?.length || 2;
      item.innerHTML = `<span class="avatar">${escapeHtml(initials(displayName(conversation)))}</span><span class="chat-item-copy"><b>${escapeHtml(displayName(conversation))}</b><small>${count} members · ${escapeHtml(conversation.lastMessage || "Open conversation")}</small></span>`;
      item.onclick = () => openConversation(conversation);
      $("chatList").append(item);
    });
  }, error => toast("Chat list: " + error.message));
}
function statusMarkup(message) {
  const recipients = (message.participants || []).filter(uid => uid !== message.senderId);
  const delivered = recipients.length > 0 && recipients.every(uid => (message.deliveredTo || []).includes(uid));
  const read = recipients.length > 0 && recipients.every(uid => (message.readBy || []).includes(uid));
  if (read) return '<span class="ticks read" title="Seen by everyone">✓✓</span>';
  if (delivered) return '<span class="ticks delivered" title="Delivered to everyone">✓✓</span>';
  return '<span class="ticks" title="Sent">✓</span>';
}
async function markDelivered(message) {
  if (message.senderId === currentUser.uid || (message.deliveredTo || []).includes(currentUser.uid)) return;
  try { await updateDoc(doc(db, "messages", message.id), { deliveredTo:arrayUnion(currentUser.uid) }); }
  catch (error) { console.warn("Delivery receipt:", error); }
}
async function markRead(message) {
  if (message.senderId === currentUser.uid || (message.readBy || []).includes(currentUser.uid)) return;
  try {
    await updateDoc(doc(db, "messages", message.id), {
      deliveredTo:arrayUnion(currentUser.uid), readBy:arrayUnion(currentUser.uid)
    });
  } catch (error) { console.warn("Read receipt:", error); }
}
async function openConversation(conversation) {
  activeConversation = conversation;
  knownMessages = new Set();
  show("emptyState", false); show("chatView", true);
  $("peerName").textContent = displayName(conversation);
  $("peerCode").textContent = `${conversation.participants.length} members · End-to-end encrypted`;
  $("peerAvatar").textContent = initials(displayName(conversation));
  $("memberSummary").textContent = (conversation.memberProfiles || [])
    .map(p => p.uid === currentUser.uid ? "You" : p.name).join(", ");
  if (stopMessages) stopMessages();
  const q = query(collection(db, "messages"), where("conversationId", "==", conversation.id));
  stopMessages = onSnapshot(q, async snapshot => {
    const messages = snapshot.docs.map(d => ({ id:d.id, ...d.data() }))
      .sort((a,b) => (a.createdAt?.toMillis?.() || 0) - (b.createdAt?.toMillis?.() || 0));
    $("messages").innerHTML = "";
    for (const message of messages) {
      if (!knownMessages.has(message.id)) {
        knownMessages.add(message.id);
        if (message.senderId !== currentUser.uid) {
          await markDelivered(message);
          if (document.visibilityState === "visible" && document.hasFocus()) await markRead(message);
          // Background notifications are handled by the global incoming-message listener.
        }
      } else if (message.senderId !== currentUser.uid &&
          document.visibilityState === "visible" && document.hasFocus()) {
        await markRead(message);
      }
      let body = "[Unable to decrypt this message on this device]";
      try { body = await decryptMessage(message); } catch (error) { console.warn(error); }
      const bubble = document.createElement("div");
      bubble.className = "bubble " + (message.senderId === currentUser.uid ? "mine" : "theirs");
      const time = message.createdAt?.toDate?.().toLocaleTimeString?.([], { hour:"2-digit", minute:"2-digit" }) || "Sending…";
      const sender = message.senderId === currentUser.uid ? "You" :
        ((conversation.memberProfiles || []).find(p => p.uid === message.senderId)?.name || "Member");
      bubble.innerHTML = `${message.participants.length > 2 ? `<small class="sender-name">${escapeHtml(sender)}</small>` : ""}<div>${escapeHtml(body)}</div><time>${time}${message.senderId === currentUser.uid ? statusMarkup(message) : ""}</time>`;
      $("messages").append(bubble);
    }
    $("messages").scrollTop = $("messages").scrollHeight;
  }, error => toast("Message error: " + error.message));
}
async function encryptMessage(text, conversation) {
  const aes = await crypto.subtle.generateKey({ name:"AES-GCM", length:256 }, true, ["encrypt","decrypt"]);
  const raw = await crypto.subtle.exportKey("raw", aes), iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, aes, encoder.encode(text));
  const wrappedKeys = {};
  for (const member of conversation.memberProfiles) {
    const publicKey = await crypto.subtle.importKey("jwk", member.publicKey, { name:"RSA-OAEP", hash:"SHA-256" }, false, ["encrypt"]);
    wrappedKeys[member.uid] = b64(await crypto.subtle.encrypt({ name:"RSA-OAEP" }, publicKey, raw));
  }
  return { ciphertext:b64(cipher), iv:b64(iv), wrappedKeys };
}
async function decryptMessage(message) {
  if (!privateKey) throw Error("Private key is not available on this device.");
  let wrapped;
  if (message.wrappedKeys) wrapped = message.wrappedKeys[currentUser.uid];
  else wrapped = message.senderId === currentUser.uid ? message.wrappedForSender : message.wrappedForRecipient;
  if (!wrapped) throw Error("This account was not included in the encryption keys.");
  const raw = await crypto.subtle.decrypt({ name:"RSA-OAEP" }, privateKey, unb64(wrapped));
  const aes = await crypto.subtle.importKey("raw", raw, { name:"AES-GCM" }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name:"AES-GCM", iv:unb64(message.iv) }, aes, unb64(message.ciphertext));
  return decoder.decode(plain);
}
$("sendForm").addEventListener("submit", async event => {
  event.preventDefault();
  const text = $("messageInput").value.trim();
  if (!text || !activeConversation) return;
  const button = $("sendForm").querySelector("button");
  button.disabled = true;
  try {
    const encrypted = await encryptMessage(text, activeConversation);
    const recipients = activeConversation.participants.filter(uid => uid !== currentUser.uid);
    await addDoc(collection(db, "messages"), {
      ...encrypted, conversationId:activeConversation.id,
      senderId:currentUser.uid, participants:activeConversation.participants,
      recipientIds:recipients, deliveredTo:[], readBy:[],
      createdAt:serverTimestamp()
    });
    await updateDoc(doc(db, "conversations", activeConversation.id), {
      lastMessage:"New encrypted message", updatedAt:serverTimestamp()
    });
    $("messageInput").value = "";
  } catch (error) { toast("Could not send: " + error.message); }
  finally { button.disabled = false; }
});

function listenIncomingMessages() {
  if (stopIncoming) stopIncoming();
  incomingInitialized = false;
  const q = query(collection(db, "messages"), where("participants", "array-contains", currentUser.uid));
  stopIncoming = onSnapshot(q, snapshot => {
    for (const change of snapshot.docChanges()) {
      const message = { id:change.doc.id, ...change.doc.data() };
      if (change.type !== "added" || message.senderId === currentUser.uid) continue;
      markDelivered(message);
      if (incomingInitialized) {
        toast("New message received");
        if (document.visibilityState !== "visible" || !document.hasFocus()) notifyIncoming(message);
      }
    }
    incomingInitialized = true;
  }, error => toast("Notifications listener: " + error.message));
}

async function setupNotifications() {
  if (!("Notification" in window)) {
    $("notificationStatus").textContent = "Browser notifications are not supported.";
    return;
  }
  $("notificationStatus").textContent = Notification.permission === "granted"
    ? "Notifications are enabled on this browser."
    : "Enable notifications to get alerts while this site is open in the background.";
}
$("enableNotifications").onclick = async () => {
  if (!("Notification" in window)) { toast("This browser does not support notifications."); return; }
  const permission = await Notification.requestPermission();
  $("notificationStatus").textContent = permission === "granted" ? "Notifications enabled." : "Notification permission was not granted.";
  if (permission === "granted") toast("Browser notifications enabled.");
};
function notifyIncoming(message) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  const conversation = conversationCache.get(message.conversationId);
  const name = conversation ? displayName(conversation) : "SecureChat";
  try {
    const notification = new Notification("New message received", {
      body:`You have a new encrypted message in ${name}.`,
      tag:`securechat-${message.conversationId}`
    });
    notification.onclick = () => { window.focus(); if (conversation) openConversation(conversation); notification.close(); };
  } catch (error) { console.warn("Notification:", error); }
}
document.addEventListener("visibilitychange", async () => {
  if (document.visibilityState !== "visible" || !document.hasFocus() || !activeConversation) return;
  // Mark currently open conversation messages as read after the user returns.
  try {
    const q = query(collection(db, "messages"), where("conversationId", "==", activeConversation.id));
    const snapshot = await getDocs(q);
    for (const item of snapshot.docs) {
      const message = { id:item.id, ...item.data() };
      if (message.senderId !== currentUser?.uid) await markRead(message);
    }
  } catch (error) { console.warn(error); }
});
