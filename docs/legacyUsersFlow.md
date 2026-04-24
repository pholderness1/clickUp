---
title: Legacy User Testing
head:
  - [script, { src: "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js" }]
  - [script, { src: "https://cdn.jsdelivr.net/npm/gsap@3/dist/gsap.min.js" }]
---

---

## Legacy Users Baseline

<div>
  <button id="play">▶ Play</button>
  <button id="step">⏭ Step</button>
  <button id="reset">⟲ Reset</button>
</div>

<div class="mermaid" id="diagram">
sequenceDiagram
  autonumber
  participant SIS as SIS
  participant AIC as AIC
  participant AD as AD
  participant BL as Business Logic

note over SIS: SIS not a participant in these test cases
note over SIS,AD: SIS is present as system of record context only - not a record source for these tests
note over SIS,AD: PREREQUISITE STATE
note over AIC,AD: Legacy test accounts exist in AIC with all required attributes<br/>Corresponding AD accounts exist with all required attributes<br/>No link exists between AIC and AD account
note over BL: Student_To_AD mapping configured
note over AIC,AD: SETUP - Establish link via reconById

AIC->>BL: REST call - reconById targeting test user(s) via Student_To_AD mapping
activate BL
BL->>AD: Locate matching AD account by legacy username attributes
AD-->>BL: Match confirmed
BL->>AIC: Link established between AIC and AD account
deactivate BL

note over AIC,AD: ASSERT - AIC and AD account are now linked before proceeding
note over SIS,AD: TEST - Verify expected outcomes
note over AIC,AD: CLEANUP - Remove reconById link only, no accounts deleted

AIC->>AIC: Remove link between AIC and AD account established by reconById
AIC->>AD: Clear corresponding linkage attributes on AD account
AD-->>AIC: Link removal acknowledged

note over AIC,AD: Pool user accounts remain intact in both AIC and AD for reuse
note over SIS: SIS not a participant in these test cases

</div>

<style>
#diagram {
  width: 100%;
  max-width: 1200px;
  overflow-x: auto;
}

#diagram svg {
  display: block;
  width: 100%;
  height: auto;
  border: 1px solid #ddd;
  background: #fafafa;
}

button {
  margin-right: 8px;
  padding: 8px 14px;
  cursor: pointer;
}
</style>

<script setup>
import { onMounted } from 'vue'

let steps = []
let timeline
let currentStep = 0
let linkLine = null

function getNoteRole(textEl) {
  const text = textEl.textContent.trim()
  if (/SIS/.test(text)) return "external"
  if (/TEST/.test(text)) return "testing"
  if (/^AIC|^AD|^SETUP|^ASSERT|^CLEANUP/i.test(text)) return "core"
  return "default"
}

function getRole(text) {
  const name = text.trim()
  if (/^SIS$/.test(name)) return "external"
  if (/^(AIC|AD)$/.test(name)) return "core"
  return "default"
}

function styleParticipants(svg) {
  svg.querySelectorAll("text").forEach(t => {
    const group = t.closest("g")
    const rect = group?.querySelector("rect")
    if (!rect) return

    const role = getRole(t.textContent)
    if (role === "external") {
      rect.style.fill = "#f5f5f5"; rect.style.stroke = "#ccc"; t.style.fill = "#888"
    }
    if (role === "core") {
      rect.style.fill = "#e3f2fd"; rect.style.stroke = "#1e88e5"
    }
  })
}

function styleNotes(svg) {
  svg.querySelectorAll("rect.note").forEach(rect => {
    const text = rect.nextElementSibling?.tagName === "text"
      ? rect.nextElementSibling
      : rect.closest("g")?.querySelector("text")

    if (!text) return

    const role = getNoteRole(text)

    if (role === "external") {
      rect.style.fill = "#f5f5f5"; rect.style.stroke = "#ccc"; text.style.fill = "#888"
    }
    if (role === "core") {
      rect.style.fill = "#e3f2fd"; rect.style.stroke = "#1e88e5"; text.style.fill = "#1e88e5"
    }
    if (role === "testing") {
      rect.style.fill = "#e8f5e9"; rect.style.stroke = "#43a047"; text.style.fill = "#43a047"
    }
  })
}

function makeResponsive(svg) {
  const w = svg.getAttribute("width")
  const h = svg.getAttribute("height")

  if (!svg.getAttribute("viewBox") && w && h) {
    svg.setAttribute("viewBox", `0 0 ${w} ${h}`)
  }

  svg.removeAttribute("width")
  svg.removeAttribute("height")
  svg.setAttribute("preserveAspectRatio", "xMidYMid meet")
  svg.style.width = "100%"
  svg.style.height = "auto"
}

function createPersistentLink(svg) {
  const texts = svg.querySelectorAll("text")
  let aicX, adX, aicEl, adEl

  texts.forEach(t => {
    const label = t.textContent.trim()
    if (label === "AIC") { aicX = t.getBBox().x + t.getBBox().width / 2; aicEl = t }
    if (label === "AD")  { adX  = t.getBBox().x + t.getBBox().width / 2; adEl  = t }
  })

  if (!aicEl || !adEl) return

  const aicBox = aicEl.closest("g")?.querySelector("rect")?.getBBox()
  const adBox  = adEl.closest("g")?.querySelector("rect")?.getBBox()
  const y = aicBox && adBox
    ? Math.max(aicBox.y + aicBox.height, adBox.y + adBox.height) + 8
    : aicEl.getBBox().y + aicEl.getBBox().height + 8

  linkLine = document.createElementNS("http://www.w3.org/2000/svg", "line")
  linkLine.setAttribute("x1", aicX)
  linkLine.setAttribute("x2", adX)
  linkLine.setAttribute("y1", y)
  linkLine.setAttribute("y2", y)
  linkLine.setAttribute("stroke", "#ff9800")
  linkLine.setAttribute("stroke-width", 3)
  linkLine.style.opacity = 0
  svg.appendChild(linkLine)
}

function collectSteps(svg) {
  const messages = svg.querySelectorAll(".message, .messageLine0, .messageLine1")
  const notes = svg.querySelectorAll("rect.note")

  const preShowPatterns = [
    /^SIS.*$/,
    /^PRE.*$/,
    /^Legacy.*$/,
    /Student_To_AD/
  ]

  const allElements = [...notes, ...messages]
    .sort((a, b) => a.getBBox().y - b.getBBox().y)

  steps = []

  allElements.forEach(el => {
    const container = el.closest("g") ?? el
    const text = el.nextElementSibling?.tagName === "text"
      ? el.nextElementSibling
      : el.closest("g")?.querySelector("text")
    const content = text?.textContent ?? el.textContent

    const isPreShow = preShowPatterns.some(pattern => pattern.test(content))

    if (isPreShow) {
      gsap.set(container, { opacity: 1, y: 0 })
    } else {
      gsap.set(container, { opacity: 0, y: -10 })
      steps.push(container)
    }
  })
}

function highlightBL(svg, active, time) {
  svg.querySelectorAll("text").forEach(t => {
    if (t.textContent.includes("Business Logic")) {
      const rect = t.closest("g")?.querySelector("rect")
      if (!rect) return
      gsap.to(rect, { stroke: active ? "#00c853" : "#43a047", strokeWidth: active ? 4 : 2, duration: 0.3 }, time)
    }
  })
}

function buildTimeline(svg) {
  timeline = gsap.timeline({ paused: true })
  steps.forEach((el, i) => {
    const text = el.textContent || ""
    timeline.to(el, { opacity: 1, y: 0, duration: 0.4 }, i * 0.6)

    if (text.includes("Link established")) timeline.to(linkLine, { opacity: 1, duration: 0.5 }, i * 0.6)
    if (text.includes("Remove link"))     timeline.to(linkLine, { opacity: 0, duration: 0.5 }, i * 0.6)
    if (text.includes("deactivate BL"))   highlightBL(svg, false, i * 0.6)
  })
}

function stepForward() {
  if (currentStep >= steps.length) return
  gsap.to(steps[currentStep], { opacity: 1, y: 0, duration: 0.4 })
  currentStep++
}

function reset() {
  timeline.pause(0)
  currentStep = 0
  steps.forEach(el => gsap.set(el, { opacity: 0, y: -10 }))
  if (linkLine) gsap.set(linkLine, { opacity: 0 })
}

onMounted(() => {
  mermaid.initialize({ startOnLoad: false })
  mermaid.run()

  setTimeout(() => {
    const svg = document.querySelector("#diagram svg")
    if (!svg) return

    makeResponsive(svg)
    styleParticipants(svg)
    styleNotes(svg)
    createPersistentLink(svg)
    collectSteps(svg)
    buildTimeline(svg)

    document.getElementById("play").onclick  = () => timeline.play(0)
    document.getElementById("step").onclick  = stepForward
    document.getElementById("reset").onclick = reset
  }, 300)
})
</script>
