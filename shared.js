// Generic multi-step "wizard" card — purely a display layer over whatever form fields/IDs/submit
// functions live inside each .wizard-step; it only shows/hides step groups and never changes what
// those functions read or how they submit. Shared here (not index.html-only) since both index.html
// (appointment booking, career match) and auth.html (signup) use the same .wizard markup pattern.
function wizardShowStep(wizardId, stepIndex){
  const wizard = document.getElementById(wizardId);
  if(!wizard) return;
  const steps = [...wizard.querySelectorAll('.wizard-step')];
  const total = steps.length;
  stepIndex = Math.max(0, Math.min(stepIndex, total - 1));
  wizard.dataset.currentStep = stepIndex;
  steps.forEach(el => el.classList.toggle('active', Number(el.dataset.step) === stepIndex));
  wizard.querySelectorAll('.wizard-dot').forEach((el, i) => {
    el.classList.toggle('active', i === stepIndex);
    el.classList.toggle('done', i < stepIndex);
  });
  const backBtn = wizard.querySelector('.wizard-back-btn');
  const nextBtn = wizard.querySelector('.wizard-next-btn');
  if(backBtn) backBtn.disabled = stepIndex === 0;
  if(nextBtn) nextBtn.style.display = stepIndex === total - 1 ? 'none' : '';
}

function wizardNext(wizardId){
  const wizard = document.getElementById(wizardId);
  if(!wizard) return;
  wizardShowStep(wizardId, Number(wizard.dataset.currentStep || 0) + 1);
}

function wizardBack(wizardId){
  const wizard = document.getElementById(wizardId);
  if(!wizard) return;
  wizardShowStep(wizardId, Number(wizard.dataset.currentStep || 0) - 1);
}

function wizardReset(wizardId){
  wizardShowStep(wizardId, 0);
}

function blobToBase64(blob){
  return new Promise((resolve, reject)=>{
    const reader = new FileReader();
    // Split on the fixed ';base64,' marker, not a bare comma — a media blob's own mime type can
    // legitimately contain commas (e.g. 'video/webm;codecs=vp8,opus'), which a naive
    // .split(',')[1] would cut into instead of the actual payload.
    reader.onloadend = () => resolve(reader.result.split(';base64,')[1]);
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
}

const SKILLS = ["JavaScript","Python","SQL","Data Analysis","Excel","Software Development","Cloud Computing",
"Accounting","Financial Modeling","Digital Marketing","Content Writing","Graphic Design","UI/UX Design",
"Social Media Management","Civil Engineering","Mechanical Engineering","Electrical Engineering",
"Renewable Energy","Project Management","Customer Service","Sales","Business Development",
"Supply Chain","Procurement","Logistics","Agronomy","Nursing","Pharmacy","Medical Lab Science",
"Human Resources","Recruiting","Networking","Cybersecurity","Petroleum Engineering","Teaching",
"Legal Practice","Hospitality Management","Public Administration","Architecture","Quantity Surveying",
"Insurance Underwriting","Banking Operations","Journalism","Video Editing",
"Biology","Chemistry","Physics","Environmental Science","Laboratory Skills","Geology"];

const PHONE_COUNTRY_CODES = [
  {cc:"+234", flag:"🇳🇬"},
  {cc:"+1", flag:"🇺🇸"},
  {cc:"+44", flag:"🇬🇧"},
  {cc:"+233", flag:"🇬🇭"},
  {cc:"+27", flag:"🇿🇦"},
  {cc:"+254", flag:"🇰🇪"}
];

function populatePhoneCountrySelect(selectId){
  const sel = document.getElementById(selectId);
  sel.innerHTML = PHONE_COUNTRY_CODES.map(c => `<option value="${c.cc}">${c.flag} ${c.cc}</option>`).join('');
  sel.value = '+234';
}

function formatPhoneWithCountryCode(cc, number){
  const cleaned = (number || '').trim().replace(/^0+/, '');
  return cleaned ? cc + ' ' + cleaned : '';
}

// Live input mask: groups digits as "XXX XXX XXXX" for +234 (the vast majority of this app's
// users) while leaving other country codes as raw digits, since we don't know their national
// formatting conventions and a wrong-shaped mask is worse than no mask.
function formatPhoneInputLive(inputEl, ccSelectEl){
  const cc = ccSelectEl ? ccSelectEl.value : '+234';
  let digits = inputEl.value.replace(/\D/g, '');
  if(cc !== '+234'){ inputEl.value = digits.slice(0, 10); return; }
  // Nigerians naturally type the local trunk prefix ("0803...") even though it's paired with a
  // +234 country code selector — strip it live so the mask matches what formatPhoneWithCountryCode
  // saves, instead of grouping the leading 0 into the number itself.
  digits = digits.replace(/^0+/, '').slice(0, 10);
  const parts = [digits.slice(0, 3), digits.slice(3, 6), digits.slice(6, 10)].filter(Boolean);
  inputEl.value = parts.join(' ');
}

// Splits a stored phone string like "+234 803 123 4567" back into {cc, number} for editing.
// Falls back to +234 for numbers saved before this country-code field existed.
function splitPhoneCountryCode(fullPhone){
  const value = (fullPhone || '').trim();
  for(const c of PHONE_COUNTRY_CODES){
    if(value.startsWith(c.cc)) return {cc: c.cc, number: value.slice(c.cc.length).trim()};
  }
  return {cc: '+234', number: value};
}

const LOCATIONS = {
  // South West
  "Lagos": ["Lagos","Ikeja","Lekki","Victoria Island","Surulere","Ikorodu","Badagry","Epe"],
  "Oyo": ["Ibadan","Ogbomoso","Oyo Town","Iseyin","Saki"],
  "Ogun": ["Abeokuta","Sagamu","Ijebu-Ode","Ota","Ilaro"],
  "Osun": ["Osogbo","Ile-Ife","Ilesa","Iwo","Ede"],
  "Ekiti": ["Ado-Ekiti","Ikere-Ekiti","Efon-Alaaye","Ikole-Ekiti"],
  "Ondo": ["Akure","Ondo Town","Owo","Ikare"],
  // North Central
  "FCT": ["Abuja","Gwagwalada","Kuje","Bwari"],
  "Kwara": ["Ilorin","Offa","Omu-Aran","Jebba"],
  "Benue": ["Makurdi","Gboko","Otukpo","Katsina-Ala"],
  "Kogi": ["Lokoja","Okene","Idah","Kabba"],
  "Nasarawa": ["Lafia","Keffi","Akwanga","Nasarawa"],
  "Niger": ["Minna","Bida","Kontagora","Suleja"],
  "Plateau": ["Jos","Bukuru","Pankshin","Shendam"],
  // North West
  "Kano": ["Kano","Wudil","Gaya"],
  "Kaduna": ["Kaduna","Zaria","Kafanchan","Saminaka"],
  "Jigawa": ["Dutse","Hadejia","Gumel","Kazaure"],
  "Katsina": ["Katsina","Daura","Funtua","Malumfashi"],
  "Kebbi": ["Birnin Kebbi","Argungu","Yauri","Zuru"],
  "Sokoto": ["Sokoto","Wurno","Tambuwal","Gwadabawa"],
  "Zamfara": ["Gusau","Kaura Namoda","Talata Mafara"],
  // North East
  "Adamawa": ["Yola","Mubi","Jimeta","Numan"],
  "Bauchi": ["Bauchi","Azare","Misau","Jama'are"],
  "Borno": ["Maiduguri","Biu","Bama","Dikwa"],
  "Gombe": ["Gombe","Kaltungo","Billiri"],
  "Taraba": ["Jalingo","Wukari","Bali","Gembu"],
  "Yobe": ["Damaturu","Potiskum","Nguru","Gashua"],
  // South East
  "Abia": ["Umuahia","Aba","Ohafia","Arochukwu"],
  "Anambra": ["Awka","Onitsha","Nnewi","Ekwulobia"],
  "Ebonyi": ["Abakaliki","Afikpo","Onueke"],
  "Enugu": ["Enugu","Nsukka","Awgu","Oji River"],
  "Imo": ["Owerri","Orlu","Okigwe","Mbaise"],
  // South South
  "Rivers": ["Port Harcourt","Bonny","Ahoada","Eleme"],
  "Akwa Ibom": ["Uyo","Eket","Ikot Ekpene"],
  "Bayelsa": ["Yenagoa","Brass","Sagbama"],
  "Cross River": ["Calabar","Ikom","Ogoja"],
  "Delta": ["Asaba","Warri","Sapele","Ughelli"],
  "Edo": ["Benin City","Auchi","Ekpoma","Uromi"]
};

function createChip(containerId, targetSet, label, startSelected){
  const el = document.getElementById(containerId);
  const c = document.createElement('div');
  c.className = 'chip' + (startSelected ? ' selected' : '');
  c.textContent = label;
  c.tabIndex = 0;
  c.setAttribute('role', 'button');
  c.setAttribute('aria-pressed', startSelected ? 'true' : 'false');
  if(startSelected) targetSet.add(label);
  const toggle = ()=>{
    if(targetSet.has(label)){ targetSet.delete(label); c.classList.remove('selected'); }
    else { targetSet.add(label); c.classList.add('selected'); }
    c.setAttribute('aria-pressed', c.classList.contains('selected') ? 'true' : 'false');
    onSkillChipToggle(containerId);
  };
  c.onclick = toggle;
  c.onkeydown = (e)=>{
    if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); toggle(); }
  };
  el.appendChild(c);
  return c;
}

// On mobile, showing all ~40 skill chips at once is overwhelming — show just the 5 that actually
// have a real verified-badge challenge behind them (see SKILL_CHALLENGE_SKILLS in index.html), so
// every visible chip on a small screen corresponds to a skill someone can actually get verified
// on. Desktop has the room to show the full list. Either way, anything else is still addable via
// the "type your own" input next to the chip field, on every section that uses buildChips.
const TOP_SKILLS = ["Python", "SQL", "Excel", "Customer Service", "JavaScript"];

// The packaged Android app's WebView doesn't always report window.innerWidth as the real
// device width (it can fall back to a desktop-style default viewport), so window width alone
// isn't reliable inside the wrapper. App.js tags its WebView's user agent with this marker as
// a second, unambiguous signal that we're inside the native app.
function isMobileApp(){
  return /BridgeNGMobileApp/.test(navigator.userAgent);
}

function buildChips(containerId, targetSet){
  const skillsToShow = (isMobileApp() || window.innerWidth <= 720) ? TOP_SKILLS : SKILLS;
  skillsToShow.forEach(sk => createChip(containerId, targetSet, sk, false));
}

function addCustomSkill(containerId, targetSet, inputId){
  const input = document.getElementById(inputId);
  const label = input.value.trim();
  if(!label) return;
  const el = document.getElementById(containerId);
  const existing = [...el.children].find(c => c.textContent.toLowerCase() === label.toLowerCase());
  if(existing){
    if(!targetSet.has(existing.textContent)){
      targetSet.add(existing.textContent);
      existing.classList.add('selected');
    }
  }else{
    createChip(containerId, targetSet, label, true);
  }
  input.value = '';
  input.focus();
  onSkillChipToggle(containerId);
}

// Page-specific pages (e.g. index.html's skill radar chart) can define handleSkillChipToggle()
// to react to skill changes; shared.js itself has no opinion on what a skill selection affects.
function onSkillChipToggle(containerId){
  if(typeof handleSkillChipToggle === 'function') handleSkillChipToggle(containerId);
}

// Selects chips already in targetSet (adding any custom ones not in the base SKILLS list).
function applySelectedSkills(containerId, targetSet, skills){
  const el = document.getElementById(containerId);
  (skills || []).forEach(label=>{
    const existing = [...el.children].find(c => c.textContent.toLowerCase() === label.toLowerCase());
    if(existing){
      targetSet.add(existing.textContent);
      existing.classList.add('selected');
    }else{
      createChip(containerId, targetSet, label, true);
    }
  });
  onSkillChipToggle(containerId);
}

function populateLocationSelect(selectId, includeAny){
  const sel = document.getElementById(selectId);
  let html = '';
  if(includeAny) html += '<option>Any location</option>';
  html += '<option>Remote</option>';
  Object.keys(LOCATIONS).forEach(state=>{
    html += `<optgroup label="${state}">` + LOCATIONS[state].map(c=>`<option>${c}</option>`).join('') + `</optgroup>`;
  });
  sel.innerHTML = html;
}

// Flat, deduped list of every city/state name for a <datalist> — used by the preferred-locations
// multi-select chip input, which (unlike a plain <select>) needs autocomplete suggestions rather
// than a fixed dropdown of options.
function populateLocationDatalist(datalistId){
  const dl = document.getElementById(datalistId);
  if(!dl) return;
  const names = new Set(['Remote']);
  Object.keys(LOCATIONS).forEach(state=>{
    names.add(state);
    LOCATIONS[state].forEach(c => names.add(c));
  });
  dl.innerHTML = [...names].sort().map(n => `<option value="${n}"></option>`).join('');
}

// --- Train Yourself: curated learning-platform search links per skill ---

function trainingResourcesFor(skill){
  const q = encodeURIComponent(skill);
  return [
    {
      platform: 'YouTube',
      badge: 'Free video lessons',
      desc: `Free tutorials and full-length courses on ${skill} from top educators and channels — the fastest way to see if it clicks for you.`,
      url: `https://www.youtube.com/results?search_query=${q}+course`
    },
    {
      platform: 'Udemy',
      badge: 'Certificate on completion',
      desc: `Structured, self-paced ${skill} courses with a certificate of completion you can add straight to your CV or LinkedIn.`,
      url: `https://www.udemy.com/courses/search/?q=${q}`
    },
    {
      platform: 'Khan Academy',
      badge: 'Free, at your own pace',
      desc: `Free, structured lessons and practice exercises related to ${skill} — best for building strong fundamentals.`,
      url: `https://www.khanacademy.org/search?page_search_query=${q}`
    },
    {
      platform: 'Coursera',
      badge: 'University-backed certificates',
      desc: `University- and industry-backed ${skill} courses and professional certificates, several with free audit options.`,
      url: `https://www.coursera.org/search?query=${q}`
    }
  ];
}

// --- Bridge NG account API client ---

async function apiRequest(path, method, body){
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin'
  });
  let data = {};
  try{ data = await res.json(); }catch(e){ /* no body */ }
  if(!res.ok){
    // Never let a bare HTTP status code reach the UI — fall back to something a person can act on.
    throw new Error(data.error || 'Something went wrong on our end. Please try again in a moment.');
  }
  return data;
}

function apiSignup(payload){ return apiRequest('/api/signup', 'POST', payload); }
function apiLogin(email, password){ return apiRequest('/api/login', 'POST', {email, password}); }
function apiLogout(){ return apiRequest('/api/logout', 'POST', {}); }
function apiDeleteAccount(password){ return apiRequest('/api/account/delete', 'POST', {password}); }

function apiEmployerSignup(payload){ return apiRequest('/api/employer/signup', 'POST', payload); }
function apiEmployerLogin(email, password){ return apiRequest('/api/employer/login', 'POST', {email, password}); }
function apiEmployerLogout(){ return apiRequest('/api/employer/logout', 'POST', {}); }
function apiEmployerMe(){ return apiRequest('/api/employer/me', 'GET'); }
function apiEmployerSubscribe(billingCycle){ return apiRequest('/api/employer/subscribe', 'POST', {billingCycle}); }
function apiListBanks(){ return apiRequest('/api/employer/banks', 'GET'); }
function apiBankResolve(accountNumber, bankCode){ return apiRequest(`/api/employer/bank/resolve?accountNumber=${encodeURIComponent(accountNumber)}&bankCode=${encodeURIComponent(bankCode)}`, 'GET'); }
function apiSaveBankAccount(payload){ return apiRequest('/api/employer/bank', 'POST', payload); }
function apiGetPipeline(){ return apiRequest('/api/employer/pipeline', 'GET'); }
function apiSetPipelineStage(candidateUserId, stage){ return apiRequest('/api/employer/pipeline', 'POST', {candidateUserId, stage}); }
function apiListTeamMembers(){ return apiRequest('/api/employer/team', 'GET'); }
function apiAddTeamMember(payload){ return apiRequest('/api/employer/team/add', 'POST', payload); }
function apiRemoveTeamMember(memberId){ return apiRequest('/api/employer/team/remove', 'POST', {memberId}); }
function apiListCandidateNotes(candidateUserId){ return apiRequest(`/api/employer/candidate-notes?candidateUserId=${encodeURIComponent(candidateUserId)}`, 'GET'); }
function apiAddCandidateNote(candidateUserId, note){ return apiRequest('/api/employer/candidate-notes', 'POST', {candidateUserId, note}); }
function apiGetCandidateVotes(candidateUserId){ return apiRequest(`/api/employer/candidate-votes?candidateUserId=${encodeURIComponent(candidateUserId)}`, 'GET'); }
function apiSetCandidateVote(candidateUserId, vote){ return apiRequest('/api/employer/candidate-votes', 'POST', {candidateUserId, vote}); }
function apiMe(){ return apiRequest('/api/me', 'GET'); }
function apiSaveProfile(payload){ return apiRequest('/api/profile', 'PUT', payload); }
function apiSaveSettings(payload){ return apiRequest('/api/profile/settings', 'PUT', payload); }
function apiSavePublicProfile(payload){ return apiRequest('/api/profile/public-profile', 'PUT', payload); }
function apiSaveResume(payload){ return apiRequest('/api/profile/resume', 'PUT', payload); }
function apiSavePitch(payload){ return apiRequest('/api/profile/pitch', 'PUT', payload); }
function apiGetCandidatePitch(userId){ return apiRequest('/api/candidate-pitch?userId=' + encodeURIComponent(userId), 'GET'); }
function apiGetSkillChallenge(skill){ return apiRequest('/api/skill-challenge?skill=' + encodeURIComponent(skill), 'GET'); }
function apiSubmitSkillChallenge(payload){ return apiRequest('/api/skill-challenge/submit', 'POST', payload); }
function apiChat(messages, context){ return apiRequest('/api/chat', 'POST', {messages, context}); }

function apiListJobs(){ return apiRequest('/api/jobs', 'GET'); }
function apiCreateSavedSearch(payload){ return apiRequest('/api/saved-searches', 'POST', payload); }
function apiJoinAppWaitlist(payload){ return apiRequest('/api/app-waitlist', 'POST', payload); }
function apiReportJob(payload){ return apiRequest('/api/report-job', 'POST', payload); }
function apiGetProfileInsights(){ return apiRequest('/api/profile/insights', 'GET'); }
function apiGetSqlPlaygroundChallenges(){ return apiRequest('/api/sql-playground/challenges', 'GET'); }
function apiSubmitSqlPlaygroundQuery(payload){ return apiRequest('/api/sql-playground/submit', 'POST', payload); }
function apiCreateAsyncInterview(payload){ return apiRequest('/api/async-interview/create', 'POST', payload); }
function apiListMyAsyncInterviews(){ return apiRequest('/api/async-interview/mine', 'GET'); }
function apiSubmitAsyncInterviewAnswer(payload){ return apiRequest('/api/async-interview/answer', 'POST', payload); }
function apiGetAsyncInterviewDetail(id){ return apiRequest(`/api/async-interview/detail?id=${encodeURIComponent(id)}`, 'GET'); }

// Mirrors server.py's slugify() exactly, so a link built here resolves to the same job the
// server would generate the URL for — only the leading numeric id is ever actually used to look
// the job up, this just keeps the URL text matching for a cleaner/more credible shared link.
function jsSlugify(text){
  const cleaned = (text || '').replace(/[^a-zA-Z0-9\s-]/g, '').trim().toLowerCase().replace(/[\s-]+/g, '-');
  return cleaned.slice(0, 80).replace(/^-+|-+$/g, '') || 'role';
}

function jobSeoUrl(dbId, title, company){
  return `/jobs/${dbId}-${jsSlugify(title)}-at-${jsSlugify(company)}`;
}
function apiListSavedSearches(){ return apiRequest('/api/saved-searches', 'GET'); }
function apiDeleteSavedSearch(id){ return apiRequest('/api/saved-searches/delete', 'POST', {id}); }
function apiFollowCompany(company){ return apiRequest('/api/follow-company', 'POST', {company}); }
function apiUnfollowCompany(company){ return apiRequest('/api/unfollow-company', 'POST', {company}); }
function apiListFollowedCompanies(){ return apiRequest('/api/followed-companies', 'GET'); }
function apiListNotifications(){ return apiRequest('/api/notifications', 'GET'); }
function apiMarkNotificationsRead(){ return apiRequest('/api/notifications/read', 'POST', {}); }
function apiCheckinStatus(){ return apiRequest('/api/checkin', 'GET'); }
function apiCheckin(){ return apiRequest('/api/checkin', 'POST', {}); }
function apiCampusCount(university){ return apiRequest('/api/campus-count?university=' + encodeURIComponent(university), 'GET'); }

function apiMessageStart(payload){ return apiRequest('/api/messages/start', 'POST', payload); }
function apiEmployerMessageThread(id, token){ return apiRequest(`/api/messages/employer-thread?id=${encodeURIComponent(id)}&token=${encodeURIComponent(token)}`, 'GET'); }
function apiEmployerMessageReply(conversationId, token, body){ return apiRequest('/api/messages/employer-reply', 'POST', {conversationId, token, body}); }
function apiListConversations(){ return apiRequest('/api/messages', 'GET'); }
function apiReplyToConversation(conversationId, body){ return apiRequest('/api/messages/reply', 'POST', {conversationId, body}); }
function apiMarkConversationRead(conversationId){ return apiRequest('/api/messages/read', 'POST', {conversationId}); }
function apiCreateSalaryReview(payload){ return apiRequest('/api/salary-reviews', 'POST', payload); }
function apiListSalaryReviews(company){ return apiRequest('/api/salary-reviews?company=' + encodeURIComponent(company), 'GET'); }
function apiCreateAppointment(payload){ return apiRequest('/api/appointments', 'POST', payload); }
function apiListAppointments(){ return apiRequest('/api/appointments', 'GET'); }
function apiCancelAppointment(id){ return apiRequest('/api/appointments/cancel', 'POST', {id}); }
function apiUpdateAppointmentStatus(id, status){ return apiRequest('/api/appointments/status', 'PUT', {id, status}); }
function apiCreateApplication(payload){ return apiRequest('/api/applications', 'POST', payload); }
function apiListApplications(){ return apiRequest('/api/applications', 'GET'); }
function apiUpdateApplicationStatus(id, status){ return apiRequest('/api/applications/status', 'PUT', {id, status}); }
function apiPostEmployerJob(payload){ return apiRequest('/api/employer-jobs', 'POST', payload); }
function apiFindJob(jobText){ return apiRequest('/api/resume/find-job', 'POST', {jobText}); }
function apiGenerateResumeDoc(payload){ return apiRequest('/api/resume/tailor', 'POST', payload); }
function apiExtractCvProfile(payload){ return apiRequest('/api/resume/extract-profile', 'POST', payload); }
function apiFindJobMatches(payload){ return apiRequest('/api/job-match', 'POST', payload); }

// --- Toast notifications — replaces blocking alert() popups with a non-blocking, on-brand
// message that fades in/out. Created lazily so no HTML file needs a container element added. ---

function showToast(message){
  let container = document.getElementById('toast-container');
  if(!container){
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  container.appendChild(toast);
  requestAnimationFrame(()=> toast.classList.add('show'));
  setTimeout(()=>{
    toast.classList.remove('show');
    setTimeout(()=> toast.remove(), 250);
  }, 4000);
}

// --- Scroll-reveal — fades/slides static sections in as they enter the viewport. Elements start
// fully visible in CSS; only JS (via inline style) hides them right before observing, so a page
// with JS disabled or IntersectionObserver unsupported just stays visible with no motion at all,
// rather than risking permanently-hidden content. Re-running on an already-revealed element is a
// no-op (tracked via dataset.revealed) so switching tabs back and forth doesn't re-hide content. ---

function initScrollReveal(root){
  if(!('IntersectionObserver' in window)) return;
  const targets = (root || document).querySelectorAll('.card, .tip-card, .results-head');
  const toObserve = [];
  targets.forEach(el=>{
    if(el.dataset.revealed) return;
    el.dataset.revealed = 'pending';
    el.style.opacity = '0';
    el.style.transform = 'translateY(24px)';
    el.style.transition = 'opacity .6s cubic-bezier(.16,.84,.44,1), transform .6s cubic-bezier(.16,.84,.44,1)';
    toObserve.push(el);
  });
  if(!toObserve.length) return;
  const observer = new IntersectionObserver((entries)=>{
    entries.forEach(entry=>{
      if(!entry.isIntersecting) return;
      entry.target.style.opacity = '1';
      entry.target.style.transform = 'translateY(0)';
      entry.target.dataset.revealed = 'done';
      observer.unobserve(entry.target);
    });
  }, {threshold:0.08});
  toObserve.forEach(el=> observer.observe(el));
}

// --- Confetti — a small celebratory burst for genuine "moment" actions (signup, first
// application), not overused on every routine success. Plain DOM + CSS animation, no canvas or
// external library, so it costs nothing when it isn't called. ---

function celebrate(){
  const colors = ['#1B2A4A', '#DB9A3C', '#2F6E4F', '#9C6A1F'];
  const container = document.createElement('div');
  container.className = 'confetti-container';
  for(let i = 0; i < 36; i++){
    const piece = document.createElement('i');
    piece.style.left = Math.random() * 100 + 'vw';
    piece.style.background = colors[i % colors.length];
    piece.style.animationDelay = (Math.random() * 0.3) + 's';
    piece.style.animationDuration = (2.2 + Math.random() * 1.2) + 's';
    piece.style.transform = `rotate(${Math.random() * 360}deg)`;
    container.appendChild(piece);
  }
  document.body.appendChild(container);
  setTimeout(()=> container.remove(), 3800);
}

// --- Friendly fallback copy for AI-related failures — never surface raw codes/stack traces. ---

function friendlyErrorMessage(context){
  const fallbacks = {
    resume: "I couldn't tailor your resume right now. Please try again shortly — your resume text above is untouched.",
    coverletter: "I couldn't write your cover letter right now. Please try again shortly.",
    generic: "Something went wrong on our end. Please try again in a moment."
  };
  return fallbacks[context] || fallbacks.generic;
}
