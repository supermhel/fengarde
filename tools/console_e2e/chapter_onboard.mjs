// Chapter: connect a device. Pick the device type, read the config, tell the page which sender to wait for, then a
// real syslog line arrives over UDP 5514 and the page confirms the first event.      node chapter_onboard.mjs <outDir>
import { spawn } from "node:child_process";
import { record } from "./tourlib.mjs";

const out = process.argv[2];
const SENDER = "198.51.100.214";
await record("chapter-onboard", out, async ({ page, sleep, clickOn, nav, signIn }) => {
  await signIn("admin", { look: 300, fast: true });
  await nav("sources", 3000);                                                            // how it flows, and the honest inventory note
  await clickOn(page.locator("button", { hasText: /rsyslog/i }).first(), 3600);          // the config for a Linux host
  await clickOn(page.locator("button.btn.primary", { hasText: /copy/i }).first(), 1800);
  // which sender should the page wait for?
  const want = page.locator("input.ctl.mono").last();
  await clickOn(want, 400);
  await page.keyboard.press("Control+A");
  await page.keyboard.type(SENDER, { delay: 70 });
  await sleep(2800);                                                                      // "waiting for the first linux_ssh event"
  // the device 'sends its first line'
  const py = `import socket,time;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);t=time.strftime('%b %d %H:%M:%S').replace(' 0','  ',1);` +
    `[s.sendto(('<38>%s web-07 sshd[%d]: Failed password for invalid user guest from ${SENDER} port 5%04d ssh2'%(t,2200+i,i)).encode(),('127.0.0.1',5514)) or time.sleep(0.2) for i in range(3)]`;
  spawn("python", ["-c", py], { stdio: "ignore" });
  await page.waitForSelector(".pill.ok", { timeout: 40000 });   // throws if the page never confirms: the chapter must not be recorded without it
  await sleep(3600);                                                                      // "received · linux_ssh from 198.51.100.214"
  await nav("events", 1800);
  await clickOn(page.locator('input[type=search]'), 300);
  await page.keyboard.type(`ip:${SENDER}`, { delay: 60 });
  await sleep(3200);
  await nav("inventory", 3000);                                                           // and why it is not in Inventory
}, { posterAt: 18 });
