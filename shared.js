const SKILLS = ["JavaScript","Python","SQL","Data Analysis","Excel","Software Development","Cloud Computing",
"Accounting","Financial Modeling","Digital Marketing","Content Writing","Graphic Design","UI/UX Design",
"Social Media Management","Civil Engineering","Mechanical Engineering","Electrical Engineering",
"Renewable Energy","Project Management","Customer Service","Sales","Business Development",
"Supply Chain","Procurement","Logistics","Agronomy","Nursing","Pharmacy","Medical Lab Science",
"Human Resources","Recruiting","Networking","Cybersecurity","Petroleum Engineering","Teaching",
"Legal Practice","Hospitality Management","Public Administration","Architecture","Quantity Surveying",
"Insurance Underwriting","Banking Operations","Journalism","Video Editing"];

const LOCATIONS = {
  "Lagos": ["Lagos","Ikeja","Lekki","Victoria Island","Surulere","Ikorodu","Badagry","Epe"],
  "FCT": ["Abuja","Gwagwalada","Kuje","Bwari"],
  "Oyo": ["Ibadan","Ogbomoso","Oyo Town","Iseyin","Saki"],
  "Ogun": ["Abeokuta","Sagamu","Ijebu-Ode","Ota","Ilaro"],
  "Osun": ["Osogbo","Ile-Ife","Ilesa","Iwo","Ede"],
  "Ekiti": ["Ado-Ekiti","Ikere-Ekiti","Efon-Alaaye","Ikole-Ekiti"],
  "Kwara": ["Ilorin","Offa","Omu-Aran","Jebba"],
  "Kano": ["Kano","Wudil","Gaya"],
  "Kaduna": ["Kaduna","Zaria","Kafanchan","Saminaka"]
};

function createChip(containerId, targetSet, label, startSelected){
  const el = document.getElementById(containerId);
  const c = document.createElement('div');
  c.className = 'chip' + (startSelected ? ' selected' : '');
  c.textContent = label;
  c.onclick = ()=>{
    if(targetSet.has(label)){ targetSet.delete(label); c.classList.remove('selected'); }
    else { targetSet.add(label); c.classList.add('selected'); }
  };
  el.appendChild(c);
  return c;
}

function buildChips(containerId, targetSet){
  SKILLS.forEach(sk => createChip(containerId, targetSet, sk, false));
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
}

function populateLocationSelect(selectId, includeAny){
  const sel = document.getElementById(selectId);
  let html = '';
  if(includeAny) html += '<option>Any location</option>';
  html += '<option>Remote</option><option>Port Harcourt</option>';
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
function apiCreateAppointment(payload){ return apiRequest('/api/appointments', 'POST', payload); }
function apiListAppointments(){ return apiRequest('/api/appointments', 'GET'); }
function apiCancelAppointment(id){ return apiRequest('/api/appointments/cancel', 'POST', {id}); }
function apiCreateApplication(payload){ return apiRequest('/api/applications', 'POST', payload); }
function apiListApplications(){ return apiRequest('/api/applications', 'GET'); }
function apiPostEmployerJob(payload){ return apiRequest('/api/employer-jobs', 'POST', payload); }
function apiFindJob(jobText){ return apiRequest('/api/resume/find-job', 'POST', {jobText}); }
function apiGenerateResumeDoc(payload){ return apiRequest('/api/resume/tailor', 'POST', payload); }

// --- Friendly fallback copy for AI-related failures — never surface raw codes/stack traces. ---

function friendlyErrorMessage(context){
  const fallbacks = {
    resume: "I couldn't tailor your resume right now. Please try again shortly — your resume text above is untouched.",
    coverletter: "I couldn't write your cover letter right now. Please try again shortly.",
    generic: "Something went wrong on our end. Please try again in a moment."
  };
  return fallbacks[context] || fallbacks.generic;
}
