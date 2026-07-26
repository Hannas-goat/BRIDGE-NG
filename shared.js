const SKILLS = ["JavaScript","Python","SQL","Data Analysis","Excel","Software Development","Cloud Computing",
"Accounting","Financial Modeling","Digital Marketing","Content Writing","Graphic Design","UI/UX Design",
"Social Media Management","Civil Engineering","Mechanical Engineering","Electrical Engineering",
"Renewable Energy","Project Management","Customer Service","Sales","Business Development",
"Supply Chain","Procurement","Logistics","Agronomy","Nursing","Pharmacy","Medical Lab Science",
"Human Resources","Recruiting","Networking","Cybersecurity","Petroleum Engineering","Teaching",
"Legal Practice","Hospitality Management","Public Administration","Architecture","Quantity Surveying",
"Insurance Underwriting","Banking Operations","Journalism","Video Editing"];

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
  c.onclick = ()=>{
    if(targetSet.has(label)){ targetSet.delete(label); c.classList.remove('selected'); }
    else { targetSet.add(label); c.classList.add('selected'); }
    onSkillChipToggle(containerId);
  };
  el.appendChild(c);
  return c;
}

// On mobile, showing all ~40 skill chips at once is overwhelming — show just the 3 broadly
// useful ones and let people type/add anything else via the input next to the chip field
// (already there for every section that uses buildChips).
const MOBILE_TOP_SKILLS = ["Data Analysis", "Customer Service", "Project Management"];

// The packaged Android app's WebView doesn't always report window.innerWidth as the real
// device width (it can fall back to a desktop-style default viewport), so window width alone
// isn't reliable inside the wrapper. App.js tags its WebView's user agent with this marker as
// a second, unambiguous signal that we're inside the native app.
function isMobileApp(){
  return /BridgeNGMobileApp/.test(navigator.userAgent);
}

function buildChips(containerId, targetSet){
  const skillsToShow = (isMobileApp() || window.innerWidth <= 720) ? MOBILE_TOP_SKILLS : SKILLS;
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
function apiMe(){ return apiRequest('/api/me', 'GET'); }
function apiSaveProfile(payload){ return apiRequest('/api/profile', 'PUT', payload); }
function apiSaveResume(payload){ return apiRequest('/api/profile/resume', 'PUT', payload); }
function apiChat(messages, context){ return apiRequest('/api/chat', 'POST', {messages, context}); }

function apiListJobs(){ return apiRequest('/api/jobs', 'GET'); }
function apiCreateSavedSearch(payload){ return apiRequest('/api/saved-searches', 'POST', payload); }
function apiListSavedSearches(){ return apiRequest('/api/saved-searches', 'GET'); }
function apiDeleteSavedSearch(id){ return apiRequest('/api/saved-searches/delete', 'POST', {id}); }
function apiFollowCompany(company){ return apiRequest('/api/follow-company', 'POST', {company}); }
function apiUnfollowCompany(company){ return apiRequest('/api/unfollow-company', 'POST', {company}); }
function apiListFollowedCompanies(){ return apiRequest('/api/followed-companies', 'GET'); }
function apiListNotifications(){ return apiRequest('/api/notifications', 'GET'); }
function apiMarkNotificationsRead(){ return apiRequest('/api/notifications/read', 'POST', {}); }
function apiCheckinStatus(){ return apiRequest('/api/checkin', 'GET'); }
function apiCheckin(){ return apiRequest('/api/checkin', 'POST', {}); }
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
