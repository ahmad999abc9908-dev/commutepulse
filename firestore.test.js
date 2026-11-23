const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require("@firebase/rules-unit-testing");
const { test, before, after, beforeEach } = require("node:test");
const fs = require("node:fs");

let testEnv;
const PROJECT_ID = process.env.GCP_PROJECT || "demo-no-project";
const ALICE_UID = "alice_commuter_123";
const BOB_UID = "bob_commuter_456";

const [emulatorHost, emulatorPortStr] = (process.env.FIRESTORE_EMULATOR_HOST || "127.0.0.1:8085").split(":");
const emulatorPort = parseInt(emulatorPortStr, 10);

before(async () => {
  const rules = fs.readFileSync("./firestore.rules", "utf8");
  testEnv = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: {
      rules,
      host: emulatorHost,
      port: emulatorPort,
    },
  });
});

after(async () => {
  if (testEnv) {
    await testEnv.cleanup();
  }
});

beforeEach(async () => {
  if (testEnv) {
    await testEnv.clearFirestore();
  }
});

test("Unauthenticated users cannot read or write profiles, routes, or alerts", async () => {
  const unauthDb = testEnv.unauthenticatedContext().firestore();
  await assertFails(unauthDb.collection("users").doc(ALICE_UID).get());
  await assertFails(unauthDb.collection("users").doc(ALICE_UID).collection("routes").get());
  await assertFails(unauthDb.collection("users").doc(ALICE_UID).collection("alerts").get());
  await assertFails(
    unauthDb.collection("users").doc(ALICE_UID).collection("routes").doc("route_1").set({
      userId: ALICE_UID,
      displayLabel: "Morning Express",
      corridorTag: "Metro Blue",
      mode: "RAIL",
      durationMinutes: 28,
      distanceKm: 14.5,
      offlinePinned: true,
      encryptedPayload: "base64ciphertext==",
      payloadIv: "base64iv==",
      keyVersion: 1,
      createdAt: new Date(Date.now() - 1000),
      updatedAt: new Date(Date.now() - 1000),
    })
  );
});

test("Authenticated owner: valid user profile create, partial update, and invalid mutations", async () => {
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const created = new Date(Date.now() - 10000);

  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).set({
      userId: ALICE_UID,
      displayName: "Alice Commuter",
      themeMode: "DARK",
      biometricRequired: true,
      highContrast: false,
      voiceFeedbackEnabled: true,
      e2eeSaltBase64: "c2FsdA==",
      e2eeVerifierBase64: "dmVyaWZpZXI=",
      dashboardWidgets: ["ACTIVE_NAV", "QUICK_ROUTES", "TRANSIT_ALERTS"],
      alertCorridors: ["Metro Blue", "Central Rail"],
      lastBackupAtMillis: Date.now() - 5000,
      createdAt: created,
      updatedAt: created,
    })
  );

  // Partial preferences update
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).update({
      themeMode: "LIGHT",
      biometricRequired: false,
      updatedAt: new Date(Date.now() - 1000),
    })
  );

  // Partial backup timestamp update
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).update({
      lastBackupAtMillis: Date.now(),
      updatedAt: new Date(Date.now() - 500),
    })
  );

  // Reject invalid theme enum
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).update({
      themeMode: "NEON_PINK",
      updatedAt: new Date(Date.now() - 500),
    })
  );

  // Reject immutable createdAt mutation
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).update({
      createdAt: new Date(Date.now() - 500),
      updatedAt: new Date(Date.now() - 500),
    })
  );

  // Reject future timestamp
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).update({
      themeMode: "DARK",
      updatedAt: new Date(Date.now() + 60000),
    })
  );
});

test("Authenticated owner: encrypted routes CRUD, @DocumentId exclusion, and cross-user isolation", async () => {
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();
  const created = new Date(Date.now() - 10000);

  // Valid route create (no `id` field inside document body)
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("routes").doc("route_home_work").set({
      userId: ALICE_UID,
      displayLabel: "Morning Express",
      corridorTag: "Metro Blue",
      mode: "RAIL",
      durationMinutes: 28,
      distanceKm: 14.5,
      offlinePinned: true,
      encryptedPayload: "aes256gcmciphertext==",
      payloadIv: "randomiv12bytes==",
      keyVersion: 1,
      createdAt: created,
      updatedAt: created,
    })
  );

  // Empty or populated list query succeeds for owner
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("routes").get()
  );

  // Toggle offline pinning partial update
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("routes").doc("route_home_work").update({
      offlinePinned: false,
      updatedAt: new Date(Date.now() - 1000),
    })
  );

  // Reject ghost `id` field in body
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).collection("routes").doc("route_ghost").set({
      id: "route_ghost",
      userId: ALICE_UID,
      displayLabel: "Ghost",
      corridorTag: "Metro Blue",
      mode: "TRANSIT",
      durationMinutes: 20,
      distanceKm: 5.0,
      offlinePinned: true,
      encryptedPayload: "abc==",
      payloadIv: "iv==",
      keyVersion: 1,
      createdAt: created,
      updatedAt: created,
    })
  );

  // Cross-user access denied
  await assertFails(
    bobDb.collection("users").doc(ALICE_UID).collection("routes").doc("route_home_work").get()
  );
  await assertFails(
    bobDb.collection("users").doc(ALICE_UID).collection("routes").get()
  );
  await assertFails(
    bobDb.collection("users").doc(ALICE_UID).collection("routes").doc("route_home_work").update({
      offlinePinned: true,
      updatedAt: new Date(Date.now() - 500),
    })
  );
});

test("Authenticated owner: transit and account alerts CRUD and negative checks", async () => {
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();
  const created = new Date(Date.now() - 8000);

  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("alerts").doc("alert_01").set({
      userId: ALICE_UID,
      category: "TRANSIT",
      severity: "ADVISORY",
      corridor: "Metro Blue",
      title: "Signal timing adjustment at Union Hub",
      encryptedDetails: "encrypted_alert_details==",
      detailsIv: "iv_bytes==",
      acknowledged: false,
      createdAt: created,
      updatedAt: created,
    })
  );

  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("alerts").doc("alert_01").update({
      acknowledged: true,
      updatedAt: new Date(Date.now() - 1000),
    })
  );

  // Reject tampering with alert severity on update
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).collection("alerts").doc("alert_01").update({
      severity: "CRITICAL",
      updatedAt: new Date(Date.now() - 500),
    })
  );

  // Cross-user alert access denied
  await assertFails(
    bobDb.collection("users").doc(ALICE_UID).collection("alerts").get()
  );
});
