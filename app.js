const API = "http://127.0.0.1:5000";
let currentUser = null;

// DOM Elements
const homeView = document.getElementById("homeView");
const loginView = document.getElementById("loginView");
const adminLoginView = document.getElementById("adminLoginView");
const registerView = document.getElementById("registerView");
const dashboard = document.getElementById("dashboard");
const homeGuest = document.getElementById("homeGuest");
const homeUser = document.getElementById("homeUser");
const homeRole = document.getElementById("homeRole");
const homeName = document.getElementById("homeName");
const regName = document.getElementById("regName");
const regEmail = document.getElementById("regEmail");
const regPassword = document.getElementById("regPassword");
const regHouseNumber = document.getElementById("regHouseNumber");
const regMsg = document.getElementById("regMsg");
const loginEmail = document.getElementById("loginEmail");
const loginPassword = document.getElementById("loginPassword");
const loginRole = document.getElementById("loginRole");
const loginMsg = document.getElementById("loginMsg");
const adminLoginEmail = document.getElementById("adminLoginEmail");
const adminLoginPassword = document.getElementById("adminLoginPassword");
const adminLoginRole = document.getElementById("adminLoginRole");
const adminLoginMsg = document.getElementById("adminLoginMsg");
const userName = document.getElementById("userName");
const residentNav = document.getElementById("residentNav");
const adminNav = document.getElementById("adminNav");
const workerNav = document.getElementById("workerNav");
const userList = document.getElementById("userList");
const complaintForm = document.getElementById("complaintForm");
const complaintTitle = document.getElementById("complaintTitle");
const complaintDescription = document.getElementById("complaintDescription");
const complaintCategory = document.getElementById("complaintCategory");
const complaintImage = document.getElementById("complaintImage");
const imagePreview = document.getElementById("imagePreview");
const myComplaintList = document.getElementById("myComplaintList");
const allComplaintList = document.getElementById("allComplaintList");
const adminComplaintList = document.getElementById("adminComplaintList");
const adminComplaintHeader = document.getElementById("adminComplaintHeader");
const pollList = document.getElementById("pollList");
const adminPollList = document.getElementById("adminPollList");
const createPollForm = document.getElementById("createPollForm");
const pollQuestionInput = document.getElementById("pollQuestionInput");
const pollDescriptionInput = document.getElementById("pollDescriptionInput");
const createPollMsg = document.getElementById("createPollMsg");
const adminPollListView = document.getElementById("adminPollListView");
const adminPollCreateView = document.getElementById("adminPollCreateView");
const changePasswordForm = document.getElementById("changePasswordForm");
const currentPasswordInput = document.getElementById("currentPassword");
const newPasswordInput = document.getElementById("newPassword");
const passwordMsg = document.getElementById("passwordMsg");
const registrationRequestsList = document.getElementById("registrationRequestsList");
const addUserForm = document.getElementById("addUserForm");
const addUserMsg = document.getElementById("addUserMsg");
// DOM elements for alert feature
const residentAlertsContainer = document.getElementById("residentAlertsContainer");
const createAlertForm = document.getElementById("createAlertForm");
const alertMessage = document.getElementById("alertMessage");
const createAlertMsg = document.getElementById("createAlertMsg");
const adminAlertList = document.getElementById("adminAlertList");

// DOM elements for house number change
const changeHouseNumberForm = document.getElementById("changeHouseNumberForm");
const currentHouseNumberDisplay = document.getElementById("currentHouseNumberDisplay");
const newHouseNumberInput = document.getElementById("newHouseNumber");
const houseChangeMsg = document.getElementById("houseChangeMsg");
const houseChangeRequestsList = document.getElementById("houseChangeRequestsList");

// AI MODAL ELEMENTS
const aiModeModal = document.getElementById("aiModeModal");
const aiInputArea = document.getElementById("aiInputArea");
const aiSearchButton = document.getElementById("aiSearchButton");

// About Us Modal Element
const aboutUsModal = document.getElementById("aboutUsModal");

// --- THEME TOGGLE FUNCTIONALITY ---
function toggleTheme() {
    const body = document.body;
    const themeBtn = document.getElementById('themeToggle');
    
    body.classList.toggle('dark-mode');
    
    if (body.classList.contains('dark-mode')) {
        localStorage.setItem('theme', 'dark');
        themeBtn.textContent = '🌙'; // Moon icon
        themeBtn.title = "Switch to Light Mode";
    } else {
        localStorage.setItem('theme', 'light');
        themeBtn.textContent = '☀️'; // Sun icon
        themeBtn.title = "Switch to Dark Mode";
    }
}

// Initialize Theme on Load
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme');
    const themeBtn = document.getElementById('themeToggle');
    
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-mode');
        if(themeBtn) {
            themeBtn.textContent = '🌙';
            themeBtn.title = "Switch to Light Mode";
        }
    }
});


// View switching functions
function showHome() {
  console.log("Showing home view");
  homeView.classList.remove("hidden");
  loginView.classList.add("hidden");
  adminLoginView.classList.add("hidden");
  registerView.classList.add("hidden");
  dashboard.classList.add("hidden");
  if (currentUser) {
    homeGuest.classList.add("hidden");
    homeUser.classList.remove("hidden");
    homeRole.textContent = currentUser.role.toUpperCase();
    homeName.textContent = currentUser.name;
  } else {
    homeGuest.classList.remove("hidden");
    homeUser.classList.add("hidden");
  }
}

function showLogin() {
  console.log("Showing resident login view");
  loginView.classList.remove("hidden");
  homeView.classList.add("hidden");
  adminLoginView.classList.add("hidden");
  registerView.classList.add("hidden");
  dashboard.classList.add("hidden");
  loginMsg.innerHTML = "";
  loginRole.value = "resident";
}

function showAdminLogin() {
  console.log("Showing admin login view");
  adminLoginView.classList.remove("hidden");
  loginView.classList.add("hidden");
  homeView.classList.add("hidden");
  registerView.classList.add("hidden");
  dashboard.classList.add("hidden");
  adminLoginMsg.innerHTML = "";
  adminLoginRole.value = "admin";
}

function showRegister() {
  console.log("Showing register view");
  registerView.classList.remove("hidden");
  homeView.classList.add("hidden");
  loginView.classList.add("hidden");
  adminLoginView.classList.add("hidden");
  dashboard.classList.add("hidden");
  regMsg.innerHTML = "";
}

function showDashboard() {
  console.log("Showing dashboard, currentUser:", currentUser);
  if (!currentUser) {
    console.log("No current user, redirecting to home");
    showHome();
    return;
  }
  homeView.classList.add("hidden");
  loginView.classList.add("hidden");
  adminLoginView.classList.add("hidden");
  registerView.classList.add("hidden");
  dashboard.classList.remove("hidden");
  userName.textContent = currentUser.name;
  
  const userHouse = document.getElementById("userHouse");
  if (currentUser.role === "resident" && currentUser.house_number) {
    userHouse.textContent = `House: ${currentUser.house_number}`;
    userHouse.style.display = "inline-block";
  } else {
    userHouse.textContent = "";
    userHouse.style.display = "none";
  }
  
  residentNav.classList.add("hidden");
  adminNav.classList.add("hidden");
  workerNav?.classList.add("hidden");
  residentAlertsContainer.innerHTML = ''; 

  // Set up navs and load initial data based on role
  if (currentUser.role === "resident") {
    residentNav.classList.remove("hidden");
    loadAlertsForResident();
  } else if (currentUser.role === "worker") {
    workerNav?.classList.remove("hidden");
    adminComplaintHeader.textContent = "Society Complaints";
  } else if (currentUser.role === "admin") {
    adminNav.classList.remove("hidden");
    adminComplaintHeader.textContent = "My Society Complaints";
    loadUsers();
    loadRegistrationRequests();
  }

  // Determine the default section based on role
  let defaultSection;
  if (currentUser.role === "resident") {
      defaultSection = 'submit-complaint';
  } else {
      defaultSection = 'admin-complaints';
  }

  // Get the last viewed section from storage, or use the default
  const sectionToShow = localStorage.getItem('lastActiveSection') || defaultSection;

  // Show the correct section
  if (sectionToShow === 'admin-complaints') {
      const isAdmin = currentUser.role === 'admin';
      const isWorker = currentUser.role === 'worker';
      showSection(sectionToShow, isAdmin, isWorker);
  } else {
      showSection(sectionToShow);
  }
}

// AI Modal Functions
function showAiModal() {
    if (aiModeModal) {
        aiModeModal.classList.remove("hidden");
        aiInputArea.value = ''; // Clear input on open
        document.getElementById('aiResponseArea').style.display = 'none'; // Hide response area
    }
}

function closeAiModal() {
    if (aiModeModal) {
        aiModeModal.classList.add("hidden");
    }
}

// About Us Modal Functions
function showAboutUs() {
    if (aboutUsModal) {
        aboutUsModal.classList.remove("hidden");
    }
}

function closeAboutUs() {
    if (aboutUsModal) {
        aboutUsModal.classList.add("hidden");
    }
}

function showAdminPollView(view) {
  adminPollListView?.classList.add("hidden");
  adminPollCreateView?.classList.add("hidden");
  document.querySelectorAll('#admin-polls .view-switch-buttons .btn-sm').forEach(btn => btn.classList.remove('active'));

  if (view === 'list') {
    adminPollListView?.classList.remove("hidden");
    document.querySelector('#viewPollsBtn').classList.add('active');
    loadPolls(adminPollList, 'admin');
  } else if (view === 'create') {
    adminPollCreateView?.classList.remove("hidden");
    document.querySelector('#createPollBtn').classList.add('active');
    createPollForm.reset();
    createPollMsg.innerHTML = '';
  }
}

function showSection(sectionId, isAdminView = false, isWorkerView = false) { 
  const sections = document.querySelectorAll('.content-section');
  sections.forEach(section => {
    section.classList.remove('active');
  });

  document.querySelectorAll('.sidebar nav a').forEach(item => {
    item.classList.remove('active');
  });
  
  // Save the current section to localStorage to remember it after a reload
  localStorage.setItem('lastActiveSection', sectionId);

  const targetSection = document.getElementById(sectionId);
  if (targetSection) {
    targetSection.classList.add('active');
  }

  const activeNavItem = document.querySelector(`.sidebar nav a[onclick*="'${sectionId}'"]`);
  if (activeNavItem) {
    activeNavItem.classList.add('active');
  }

  switch(sectionId) {
    case 'my-complaints':
      loadComplaints(myComplaintList, 'my');
      break;
    case 'all-complaints':
      loadComplaints(allComplaintList, 'all');
      break;
    case 'society-polls':
      loadPolls(pollList, 'resident');
      break;
    case 'admin-complaints':
      loadComplaints(adminComplaintList, isAdminView ? 'admin' : 'worker');
      break;
    case 'admin-polls':
      showAdminPollView('list'); 
      break;
    case 'user-management':
      loadUsers();
      break;
    case 'registration-requests': 
      loadRegistrationRequests();
      break;
    case 'manage-alerts':
      loadAlertsForAdmin();
      break;
    case 'change-house-number':
      if (currentHouseNumberDisplay) {
        currentHouseNumberDisplay.textContent = currentUser.house_number || "Not set";
      }
      if (houseChangeMsg) houseChangeMsg.innerHTML = '';
      break;
    case 'house-change-requests':
      loadHouseChangeRequests();
      break;
    case 'payment-section':
      if (currentUser) {
          document.getElementById('payName').value = currentUser.name;
          document.getElementById('payHouse').value = currentUser.house_number || 'N/A';
          loadMyPayments();
      }
      break;
    case 'admin-payments':
      loadAllSocietyPayments();
      break;
  }
}

function logout() {
  currentUser = null;
  localStorage.removeItem('currentUser');
  localStorage.removeItem('lastActiveSection'); 
  showHome();
}

// User Registration Request
document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  console.log("Registration request submitted");
  
  const data = {
    name: regName.value,
    email: regEmail.value,
    password: regPassword.value,
    house_number: regHouseNumber.value,
  };
  
  try {
    const res = await fetch(API + "/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    
    const out = await res.json();
    if (res.ok) {
      regMsg.innerHTML = `<div class="message success">${out.message}</div>`;
      document.getElementById("registerForm").reset();
    } else {
      regMsg.innerHTML = `<div class="message error">${out.error || "Registration failed"}</div>`;
    }
  } catch (error) {
    console.error("Registration error:", error);
    regMsg.innerHTML = `<div class="message error">Network error: ${error.message}</div>`;
  }
});

// Resident Login
document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const data = {
    email: loginEmail.value,
    password: loginPassword.value,
    role: "resident",
  };
  loginMsg.innerHTML = "";
  try {
    const res = await fetch(API + "/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    
    const out = await res.json();
    if (res.ok) {
      currentUser = out;
      localStorage.setItem('currentUser', JSON.stringify(currentUser));
      showDashboard();
    } else {
      loginMsg.innerHTML = `<div class="message error">${out.error || "Login failed"}</div>`;
    }
  } catch (error) {
    console.error("Login error:", error);
    loginMsg.innerHTML = `<div class="message error">Network error: ${error.message}</div>`;
  }
});

// Admin Login
document.getElementById("adminLoginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const data = {
    email: adminLoginEmail.value,
    password: adminLoginPassword.value,
    role: "admin",
  };
  adminLoginMsg.innerHTML = "";
  try {
    const res = await fetch(API + "/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    
    const out = await res.json();
    if (res.ok) {
      currentUser = out;
      localStorage.setItem('currentUser', JSON.stringify(currentUser));
      showDashboard();
    } else {
      adminLoginMsg.innerHTML = `<div class="message error">${out.error || "Login failed"}</div>`;
    }
  } catch (error) {
    console.error("Admin login error:", error);
    adminLoginMsg.innerHTML = `<div class="message error">Network error: ${error.message}</div>`;
  }
});

// Change Password
changePasswordForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const data = {
    id: currentUser.id,
    current_password: currentPasswordInput.value,
    new_password: newPasswordInput.value,
  };
  
  try {
    const res = await fetch(API + "/change_password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    
    const out = await res.json();
    if (res.ok) {
      passwordMsg.innerHTML = `<div class="message success">${out.message}</div>`;
      changePasswordForm.reset();
    } else {
      passwordMsg.innerHTML = `<div class="message error">${out.error}</div>`;
    }
  } catch (error) {
    passwordMsg.innerHTML = `<div class="message error">Network error: ${error.message}</div>`;
  }
});

// Complaint Submission
complaintForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const formData = new FormData();
  formData.append("title", complaintTitle.value);
  formData.append("description", complaintDescription.value);
  formData.append("category", complaintCategory.value);
  formData.append("user_id", currentUser.id);
  
  if (complaintImage.files.length > 0) {
    formData.append("image", complaintImage.files[0]);
  }
  
  document.getElementById("complaintMsg").innerHTML = `<div class="message info">Submitting complaint...</div>`;

  try {
    const res = await fetch(API + "/submit_complaint", {
      method: "POST",
      body: formData,
    });
    
    const out = await res.json();
    if (res.ok) {
      document.getElementById("complaintMsg").innerHTML = `<div class="message success">${out.message}</div>`;
      complaintForm.reset();
      imagePreview.innerHTML = '';
      loadComplaints(myComplaintList, 'my');
    } else {
      document.getElementById("complaintMsg").innerHTML = `<div class="message error">${out.error || "Submission failed"}</div>`;
    }
  } catch (error) {
    console.error("Complaint submission error:", error);
    document.getElementById("complaintMsg").innerHTML = `<div class="message error">Network error: ${error.message}</div>`;
  }
});

// Image Preview for Complaint Form
complaintImage?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = (event) => {
            imagePreview.innerHTML = `<p>Image ready for upload:</p><img src="${event.target.result}" alt="Image Preview" style="max-width: 150px; height: auto; border-radius: 8px; margin-top: 10px;">`;
        };
        reader.readAsDataURL(file);
    } else {
        imagePreview.innerHTML = '';
    }
});

async function updateComplaintStatus(complaintId, newStatus) {
    if (!currentUser || (currentUser.role !== 'admin' && currentUser.role !== 'worker')) {
        alert("Unauthorized action.");
        return;
    }

    try {
        const res = await fetch(`${API}/update_complaint_status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                complaint_id: complaintId, 
                new_status: newStatus,
                user_role: currentUser.role 
            })
        });

        if (res.ok) {
            if (currentUser.role === 'admin') {
              loadComplaints(adminComplaintList, 'admin');
            } else if (currentUser.role === 'worker') {
              loadComplaints(adminComplaintList, 'worker');
            }
        } else {
            const out = await res.json();
            alert(`Failed to update status: ${out.error || "Unknown error"}`);
        }
    } catch (error) {
        console.error('Error updating complaint status:', error);
        alert("Network error: Failed to update status.");
    }
}

async function reopenComplaint(complaintId) {
    if (!currentUser || currentUser.role !== 'resident') {
        alert("This action is for residents only.");
        return;
    }
    if (!confirm("Are you sure you want to reopen this complaint? This will set its status back to 'Open' for admin review.")) {
        return;
    }
    try {
        const res = await fetch(`${API}/update_complaint_status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                complaint_id: complaintId, 
                new_status: 'Open',
                user_role: currentUser.role,
                user_id: currentUser.id 
            })
        });
        const out = await res.json();
        if (res.ok) {
            alert(out.message || "Complaint reopened successfully.");
            loadComplaints(myComplaintList, 'my'); 
        } else {
            alert(`Failed to reopen complaint: ${out.error || "Unknown error"}`);
        }
    } catch (error) {
        console.error('Error reopening complaint:', error);
        alert("Network error: Failed to reopen complaint.");
    }
}

async function deleteComplaint(complaintId) {
    if (!currentUser || currentUser.role !== 'admin') {
        alert("Unauthorized action. Only administrators can delete complaints.");
        return;
    }
    if (!confirm(`Are you sure you want to permanently delete complaint #${complaintId}? This action cannot be undone.`)) {
        return;
    }

    try {
        const res = await fetch(`${API}/delete_complaint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                complaint_id: complaintId, 
                user_role: currentUser.role 
            })
        });

        if (res.ok) {
            alert(`Complaint #${complaintId} deleted successfully.`);
            loadComplaints(adminComplaintList, 'admin');
        } else {
            const out = await res.json();
            alert(`Failed to delete complaint: ${out.error || "Unknown error"}`);
        }
    } catch (error) {
        console.error('Error deleting complaint:', error);
        alert("Network error: Failed to delete complaint.");
    }
}

function applyCategoryFilter() {
    loadComplaints(document.getElementById('allComplaintList'), 'all');
}

function applyAdminCategoryFilter() {
    const viewType = (currentUser && currentUser.role === 'admin') ? 'admin' : 'worker';
    loadComplaints(document.getElementById('adminComplaintList'), viewType);
}

async function loadComplaints(targetElement, viewType = 'all') { 
  let pollQuestions = new Set();
  if (viewType === 'my' || viewType === 'all' || viewType === 'admin' || viewType === 'worker') {
      try {
          const res = await fetch(`${API}/get_polls`);
          const polls = await res.json();
          if (!polls.error) {
              pollQuestions = new Set(polls.map(p => p.question));
          }
      } catch (e) {
          console.error("Could not fetch polls for complaint indicators", e);
      }
  }

  if (!targetElement) return;
  targetElement.innerHTML = '<div class="message info">Loading complaints...</div>';
  const userId = currentUser ? currentUser.id : '';
  try {
    const res = await fetch(`${API}/get_complaints?user_id=${userId}&view_type=${viewType}`);
    const allFetchedComplaints = await res.json(); 

    if (allFetchedComplaints.error) {
      targetElement.innerHTML = `<div class="message error">${allFetchedComplaints.error}</div>`;
      return;
    }

    let categoryFilterValue = 'all';
    let dateFilterValue = '';
    let statusFilterValue = 'all';
    let houseFilterValue = '';
    if (viewType === 'all') {
        const categoryFilterEl = document.getElementById('categoryFilter');
        if (categoryFilterEl) categoryFilterValue = categoryFilterEl.value;

        const statusFilterEl = document.getElementById('statusFilter');
        if (statusFilterEl) statusFilterValue = statusFilterEl.value;

        const dateFilterEl = document.getElementById('dateFilter');
        if (dateFilterEl) dateFilterValue = dateFilterEl.value;

        const houseFilterEl = document.getElementById('houseFilter');
        if (houseFilterEl) houseFilterValue = houseFilterEl.value.trim().toLowerCase();
    } else if (viewType === 'admin' || viewType === 'worker') { 
        const categoryFilterEl = document.getElementById('adminCategoryFilter');
        if (categoryFilterEl) categoryFilterValue = categoryFilterEl.value;

        const statusFilterEl = document.getElementById('adminStatusFilter');
        if (statusFilterEl) statusFilterValue = statusFilterEl.value;

        const dateFilterEl = document.getElementById('adminDateFilter');
        if (dateFilterEl) dateFilterValue = dateFilterEl.value;

        const houseFilterEl = document.getElementById('adminHouseFilter');
        if (houseFilterEl) houseFilterValue = houseFilterEl.value.trim().toLowerCase();
    }

    const complaints = allFetchedComplaints.filter(complaint => {
        const categoryMatch = (categoryFilterValue === 'all' || complaint.category === categoryFilterValue);
        const statusMatch = (statusFilterValue === 'all' || complaint.status === statusFilterValue);
        const dateMatch = (!dateFilterValue || complaint.created_at.startsWith(dateFilterValue));
        const houseMatch = (!houseFilterValue || (complaint.house_number && complaint.house_number.toLowerCase().includes(houseFilterValue)));

        return categoryMatch && dateMatch && statusMatch && houseMatch;
    });

    if (complaints.length === 0) {
      targetElement.innerHTML = '<div class="message info">No complaints found matching the current filter.</div>';
      return;
    }

    let html = '';
    const isAdminOrWorker = viewType === 'admin' || viewType === 'worker';
    const isDeletable = viewType === 'admin';
    const isMyComplaintsView = viewType === 'my'; 

    complaints.forEach(complaint => {
      let pollIndicatorHtml = '';
      if (pollQuestions.has(complaint.title)) {
          pollIndicatorHtml = `<div class="poll-indicator">📢 This issue has been converted to a society poll for voting.</div>`;
      }
      
      let controlsHtml = '';
      if (isAdminOrWorker) {
        let statusOptions = `
          <option value="Open" ${complaint.status === 'Open' ? 'selected' : ''}>Open</option>
          <option value="in-progress" ${complaint.status === 'in-progress' ? 'selected' : ''}>In Progress</option>
          <option value="resolved" ${complaint.status === 'resolved' ? 'selected' : ''}>Resolved</option>
        `;

        controlsHtml = `
          <div class="card-actions">
            <select class="status-dropdown status-color-${complaint.status.replace(/\s/g, '-')}" onchange="updateComplaintStatus(${complaint.id}, this.value)">
              ${statusOptions}
            </select>
            ${isDeletable ? `<button type="button" class="btn btn-warning btn-small" onclick="createPollFromComplaint(\`${complaint.title.replace(/`/g, "\\`")}\`)">Create Poll</button>` : ''}
            ${isDeletable ? `<button type="button" class="btn btn-danger btn-small" onclick="deleteComplaint(${complaint.id})">Delete</button>` : ''}
          </div>
        `;
      } else if (isMyComplaintsView && complaint.status === 'resolved') {
        controlsHtml = `
            <div class="card-actions">
                <p>This complaint is resolved. If the issue persists, you can reopen it.</p>
                <button type="button" class="btn btn-warning btn-small" onclick="reopenComplaint(${complaint.id})">Reopen Complaint</button>
            </div>
        `;
      }
      
      let imageHtml = complaint.image_path ? `
          <div class="image-attachment">
              <img src="${API}/uploads/${complaint.image_path}" 
                   alt="Attached Image" 
                   class="complaint-image-thumbnail"
                   onclick="window.open('${API}/uploads/${complaint.image_path}', '_blank')">
          </div>
      ` : '';

      const isLiked = complaint.user_has_liked ? 'liked' : '';
      const likeButtonHtml = `
        <div class="like-container">
            <button type="button" id="like-btn-${complaint.id}" class="like-btn ${isLiked}" onclick="likeComplaint(event, ${complaint.id})">
                👍
            </button>
            <span id="like-count-${complaint.id}" class="like-count">${complaint.like_count}</span>
        </div>
      `;

      html += `
        <div class="card complaint-card status-${complaint.status.replace(/\s/g, '-')}">
          <h4>${complaint.title}</h4>
          ${pollIndicatorHtml}
          <p><strong>Filed by:</strong> ${complaint.user_name} (House: ${complaint.house_number})</p>
          <p><strong>Category:</strong> ${complaint.category}</p>
          <p><strong>Status:</strong> ${complaint.status}</p>
          <div class="description">${complaint.description}</div>
          ${imageHtml}
          <div class="card-footer">
            <div class="date-filed">
              Filed on: ${new Date(complaint.created_at).toLocaleDateString()}
            </div>
            ${likeButtonHtml}
          </div>
          ${controlsHtml}
        </div>
      `;
    });
    targetElement.innerHTML = html;
  } catch (error) {
    console.error('Error loading complaints:', error);
    targetElement.innerHTML = `<div class="message error">Network error: ${error.message}</div>`;
  }
}

async function likeComplaint(event, complaintId) {
    event.preventDefault();
    event.stopPropagation();
    if (!currentUser) {
        alert("You must be logged in to like a complaint.");
        return;
    }

    try {
        const res = await fetch(`${API}/like_complaint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                complaint_id: complaintId,
                user_id: currentUser.id
            })
        });

        const out = await res.json();
        if (res.ok) {
            const likeButton = document.getElementById(`like-btn-${complaintId}`);
            const likeCountSpan = document.getElementById(`like-count-${complaintId}`);
            
            if (likeButton && likeCountSpan) {
                likeCountSpan.textContent = out.new_like_count;
                if (out.action === "liked") {
                    likeButton.classList.add('liked');
                } else {
                    likeButton.classList.remove('liked');
                }
            }
        } else {
            alert(`Error: ${out.error || "Could not process like."}`);
        }
    } catch (error) {
        console.error('Error liking complaint:', error);
        alert("Network error: Could not like complaint.");
    }
}

async function createPollFromComplaint(complaintTitle) {
    if (!currentUser || currentUser.role !== 'admin') {
        alert("Unauthorized action.");
        return;
    }
    if (!confirm(`Are you sure you want to create a poll for the complaint: "${complaintTitle}"?`)) {
        return;
    }

    const data = {
        question: complaintTitle,
        description: `This poll was created from a complaint to gather resident feedback.`,
        options: ['Yes', 'No'],
        created_by: currentUser.id
    };

    try {
        const res = await fetch(API + "/create_poll", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
        });
        const out = await res.json();
        if (res.ok) {
            alert('Poll created successfully! Residents can now vote on this issue.');
            loadComplaints(adminComplaintList, 'admin'); 
            showSection('admin-polls');
        } else {
            alert(`Failed to create poll: ${out.error || "An unknown error occurred."}`);
        }
    } catch (error) {
        console.error("Poll creation from complaint error:", error);
        alert("A network error occurred while trying to create the poll.");
    }
}

async function loadPolls(targetElement, viewType = 'resident') {
  if (!targetElement) return;
  targetElement.innerHTML = '<div class="message info">Loading polls...</div>';
  const userId = currentUser ? currentUser.id : '';
  try {
    const res = await fetch(`${API}/get_polls?user_id=${userId}`);
    const polls = await res.json();
    if (polls.error) {
      targetElement.innerHTML = `<div class="message error">${polls.error}</div>`;
      return;
    }
    if (polls.length === 0) {
      targetElement.innerHTML = '<div class="message info">No polls available.</div>';
      return;
    }
    let html = '';
    polls.forEach(poll => {
      let optionsHtml = '';
      let resultsHtml = '';
      const hasVoted = poll.has_voted;
      
      if (!hasVoted && viewType === 'resident') {
        poll.options.forEach(option => {
          optionsHtml += `
            <button type="button" class="btn" onclick="votePoll(event, ${poll.id}, '${option}')" style="margin-right: 10px;">${option}</button>
          `;
        });
      } else {
        poll.options.forEach(option => {
          const voteCount = poll.vote_counts[option] || 0;
          const percentage = poll.total_votes > 0 ? ((voteCount / poll.total_votes) * 100).toFixed(1) : 0;
          const isUserVote = poll.user_vote === option;
          const votedClass = isUserVote ? 'user-voted' : '';
          resultsHtml += `
            <div class="poll-option-result">
              <p>${option} - ${voteCount} votes (${percentage}%)</p>
              <div class="progress-bar">
                <div class="progress-fill ${votedClass}" style="width: ${percentage}%;"></div>
              </div>
            </div>
          `;
        });
        optionsHtml = `<div class="poll-results-container">${resultsHtml}</div>`;
      }

      let controlsHtml = (viewType === 'admin' && currentUser.role === 'admin') ? `
        <div class="card-actions">
          <button type="button" class="btn btn-danger btn-small" onclick="deletePoll(${poll.id})">Delete Poll</button>
        </div>` : '';
      
      html += `
        <div class="card poll-item">
          <h4>${poll.question}</h4>
          ${poll.description ? `<p>${poll.description}</p>` : ''}
          <div class="poll-options-container">
            ${optionsHtml}
          </div>
          <p class="total-votes-count">${poll.total_votes} total votes</p>
          <div class="date-filed">
            Posted by ${poll.created_by_name} on ${new Date(poll.created_at).toLocaleDateString()}
          </div>
          ${controlsHtml}
        </div>
      `;
    });
    targetElement.innerHTML = html;
  } catch (error) {
    console.error('Error loading polls:', error);
    targetElement.innerHTML = `<div class="message error">Network error: ${error.message}</div>`;
  }
}

async function votePoll(event, pollId, option) {
    event.preventDefault();
    event.stopPropagation();
    if (!currentUser || currentUser.role !== 'resident') {
        alert("Only logged-in residents can vote.");
        return;
    }
    try {
        const res = await fetch(`${API}/vote_poll`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                poll_id: pollId, 
                user_id: currentUser.id,
                option: option 
            })
        });
        if (res.ok) {
            loadPolls(pollList, 'resident'); 
        } else {
            const out = await res.json();
            alert(`Failed to submit vote: ${out.error || "Unknown error"}`);
        }
    } catch (error) {
        console.error('Error voting in poll:', error);
        alert("Network error: Failed to submit vote.");
    }
}

async function deletePoll(pollId) {
    if (!currentUser || currentUser.role !== 'admin') {
        alert("Unauthorized action. Only admins can delete polls.");
        return;
    }
    if (!confirm(`Are you sure you want to permanently delete poll #${pollId}?`)) {
        return;
    }
    try {
        const res = await fetch(`${API}/delete_poll`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                poll_id: pollId, 
                user_role: currentUser.role 
            })
        });
        if (res.ok) {
            alert(`Poll #${pollId} deleted successfully.`);
            loadPolls(adminPollList, 'admin');
        } else {
            const out = await res.json();
            alert(`Failed to delete poll: ${out.error || "Unknown error"}`);
        }
    } catch (error) {
        console.error('Error deleting poll:', error);
        alert("Network error: Failed to delete poll.");
    }
}

createPollForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!currentUser || currentUser.role !== 'admin') {
        createPollMsg.innerHTML = `<div class="message error">Unauthorized.</div>`;
        return;
    }
    const data = {
        question: pollQuestionInput.value,
        description: pollDescriptionInput.value,
        options: ['Yes', 'No'],
        created_by: currentUser.id
    };
    try {
        const res = await fetch(API + "/create_poll", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
        });
        const out = await res.json();
        if (res.ok) {
            createPollMsg.innerHTML = `<div class="message success">${out.message}</div>`;
            createPollForm.reset();
            showAdminPollView('list');
        } else {
            createPollMsg.innerHTML = `<div class="message error">${out.error || "Failed"}</div>`;
        }
    } catch (error) {
        console.error("Poll creation error:", error);
        createPollMsg.innerHTML = `<div class="message error">Network error.</div>`;
    }
});

async function loadUsers() {
    const targetElement = userList;
    if (!targetElement) return;
    targetElement.innerHTML = '<div class="message info">Loading users...</div>';
    if (!currentUser || currentUser.role !== 'admin') {
        targetElement.innerHTML = `<div class="message error">Unauthorized.</div>`;
        return;
    }
    try {
        const res = await fetch(`${API}/get_users`);
        const users = await res.json();
        if (users.error) {
            targetElement.innerHTML = `<div class="message error">${users.error}</div>`;
            return;
        }
        if (users.length === 0) {
            targetElement.innerHTML = '<div class="message info">No users found.</div>';
            return;
        }
        let html = `
            <table class="user-table">
                <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>House No.</th><th>Actions</th></tr></thead>
                <tbody>`;
        users.forEach(user => {
            if (user.id === currentUser.id) return;
            html += `
                <tr>
                    <td>${user.id}</td><td>${user.name}</td><td>${user.email}</td>
                    <td><span class="badge role-${user.role}">${user.role}</span></td>
                    <td>${user.house_number || 'N/A'}</td>
                    <td><button type="button" class="btn btn-danger btn-small" onclick="deleteUser(${user.id}, '${user.name}')">Delete</button></td>
                </tr>`;
        });
        html += `</tbody></table>`;
        targetElement.innerHTML = html;
    } catch (error) {
        console.error('Error loading users:', error);
        targetElement.innerHTML = `<div class="message error">Network error.</div>`;
    }
}

async function deleteUser(userId, userName) {
    if (!currentUser || currentUser.role !== 'admin') {
        alert("Unauthorized.");
        return;
    }
    if (!confirm(`Delete user: ${userName} (ID: ${userId})?`)) {
        return;
    }
    try {
        const res = await fetch(`${API}/delete_user`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId })
        });
        if (res.ok) {
            alert(`User ${userName} deleted.`);
            loadUsers();
        } else {
            const out = await res.json();
            alert(`Failed to delete user: ${out.error || "Error"}`);
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        alert("Network error.");
    }
}

addUserForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = {
        name: document.getElementById("addUserName").value,
        email: document.getElementById("addUserEmail").value,
        password: document.getElementById("addUserPassword").value,
        role: document.getElementById("addUserRole").value,
        house_number: document.getElementById("addUserHouseNumber").value
    };
    if (!currentUser || currentUser.role !== 'admin') {
        addUserMsg.innerHTML = `<div class="message error">Unauthorized.</div>`;
        return;
    }
    try {
        const res = await fetch(API + "/add_user", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
        });
        const out = await res.json();
        if (res.ok) {
            addUserMsg.innerHTML = `<div class="message success">${out.message}</div>`;
            addUserForm.reset();
            loadUsers();
        } else {
            addUserMsg.innerHTML = `<div class="message error">${out.error || "Failed"}</div>`;
        }
    } catch (error) {
        console.error("Add user error:", error);
        addUserMsg.innerHTML = `<div class="message error">Network error.</div>`;
    }
});

async function loadRegistrationRequests() {
    const targetElement = registrationRequestsList;
    if (!targetElement) return;
    targetElement.innerHTML = '<div class="message info">Loading...</div>';
    if (!currentUser || currentUser.role !== 'admin') {
        targetElement.innerHTML = `<div class="message error">Unauthorized.</div>`;
        return;
    }
    try {
        const res = await fetch(`${API}/get_registration_requests`);
        const requests = await res.json();
        if (requests.error) {
            targetElement.innerHTML = `<div class="message error">${requests.error}</div>`;
            return;
        }
        if (requests.length === 0) {
            targetElement.innerHTML = '<div class="message info">No pending requests.</div>';
            return;
        }
        let html = '';
        requests.forEach(request => {
            html += `
                <div class="card">
                    <h4>${request.name} (House: ${request.house_number || 'N/A'})</h4>
                    <p>Email: ${request.email}</p>
                    <div class="date-filed">Requested on: ${new Date(request.created_at).toLocaleDateString()}</div>
                    <div class="card-actions">
                        <button type="button" class="btn btn-success btn-small" onclick="processRegistrationRequest(${request.id}, 'approve')">Approve</button>
                        <button type="button" class="btn btn-danger btn-small" onclick="processRegistrationRequest(${request.id}, 'reject')">Reject</button>
                    </div>
                </div>`;
        });
        targetElement.innerHTML = html;
    } catch (error) {
        console.error('Error loading requests:', error);
        targetElement.innerHTML = `<div class="message error">Network error.</div>`;
    }
}

async function processRegistrationRequest(requestId, action) {
    if (!currentUser || currentUser.role !== 'admin') {
        alert("Unauthorized.");
        return;
    }
    if (!confirm(`Are you sure you want to ${action} this request?`)) {
        return;
    }
    try {
        const res = await fetch(`${API}/process_registration_request`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ request_id: requestId, action: action })
        });
        const out = await res.json();
        if (res.ok) {
            alert(out.message);
            loadRegistrationRequests();
            if (action === 'approve') {
                loadUsers();
            }
        } else {
            alert(`Failed: ${out.error || "Error"}`);
        }
    } catch (error) {
        console.error(`Error processing request:`, error);
        alert("Network error.");
    }
}

// --- HOUSE NUMBER CHANGE ---

changeHouseNumberForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!currentUser) {
        houseChangeMsg.innerHTML = `<div class="message error">You must be logged in.</div>`;
        return;
    }
    const data = {
        user_id: currentUser.id,
        new_house_number: newHouseNumberInput.value
    };
    try {
        const res = await fetch(`${API}/request_house_change`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        const out = await res.json();
        if (res.ok) {
            houseChangeMsg.innerHTML = `<div class="message success">${out.message}</div>`;
            changeHouseNumberForm.reset();
        } else {
            houseChangeMsg.innerHTML = `<div class="message error">${out.error || "Failed"}</div>`;
        }
    } catch (error) {
        console.error('Error requesting house number change:', error);
        houseChangeMsg.innerHTML = `<div class="message error">Network error.</div>`;
    }
});

async function loadHouseChangeRequests() {
    const targetElement = houseChangeRequestsList;
    if (!targetElement) return;
    targetElement.innerHTML = '<div class="message info">Loading...</div>';
    if (!currentUser || currentUser.role !== 'admin') {
        targetElement.innerHTML = `<div class="message error">Unauthorized.</div>`;
        return;
    }
    try {
        const res = await fetch(`${API}/get_house_change_requests`);
        const requests = await res.json();
        if (requests.error) {
            targetElement.innerHTML = `<div class="message error">${requests.error}</div>`;
            return;
        }
        if (requests.length === 0) {
            targetElement.innerHTML = '<div class="message info">No pending house number change requests.</div>';
            return;
        }
        let html = '';
        requests.forEach(req => {
            html += `
                <div class="card">
                    <h4>${req.name} (${req.email})</h4>
                    <p>Current House No: <strong>${req.current_house_number}</strong></p>
                    <p>Requested House No: <strong style="color: #1a2980;">${req.requested_house_number}</strong></p>
                    <div class="date-filed">Requested on: ${new Date(req.created_at).toLocaleString()}</div>
                    <div class="card-actions">
                        <button type="button" class="btn btn-success btn-small" onclick="processHouseChangeRequest(${req.id}, 'approve')">Approve</button>
                        <button type="button" class="btn btn-danger btn-small" onclick="processHouseChangeRequest(${req.id}, 'reject')">Reject</button>
                    </div>
                </div>`;
        });
        targetElement.innerHTML = html;
    } catch (error) {
        console.error('Error loading house change requests:', error);
        targetElement.innerHTML = `<div class="message error">Network error.</div>`;
    }
}

async function processHouseChangeRequest(requestId, action) {
    if (!currentUser || currentUser.role !== 'admin') {
        alert("Unauthorized.");
        return;
    }
    if (!confirm(`Are you sure you want to ${action} this request?`)) {
        return;
    }
    try {
        const res = await fetch(`${API}/process_house_change_request`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ request_id: requestId, action: action })
        });
        const out = await res.json();
        if (res.ok) {
            alert(out.message);
            loadHouseChangeRequests();
            if (action === 'approve') {
                loadUsers(); 
            }
        } else {
            alert(`Failed: ${out.error || "Error"}`);
        }
    } catch (error) {
        console.error(`Error processing house change request:`, error);
        alert("Network error.");
    }
}

// --- ALERT MANAGEMENT ---

createAlertForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!currentUser || currentUser.role !== 'admin') {
        createAlertMsg.innerHTML = `<div class="message error">Unauthorized action.</div>`;
        return;
    }
    const data = {
        message: alertMessage.value,
        user_id: currentUser.id,
        user_role: currentUser.role
    };
    try {
        const res = await fetch(`${API}/create_alert`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        const out = await res.json();
        if (res.ok) {
            createAlertMsg.innerHTML = `<div class="message success">${out.message}</div>`;
            createAlertForm.reset();
            loadAlertsForAdmin();
        } else {
            createAlertMsg.innerHTML = `<div class="message error">${out.error || "Failed"}</div>`;
        }
    } catch (error) {
        console.error('Error creating alert:', error);
        createAlertMsg.innerHTML = `<div class="message error">Network error.</div>`;
    }
});

async function loadAlertsForAdmin() {
    if (!adminAlertList) return;
    adminAlertList.innerHTML = '<div class="message info">Loading alerts...</div>';
    try {
        const res = await fetch(`${API}/get_alerts`);
        const alerts = await res.json();
        if (alerts.error) {
            adminAlertList.innerHTML = `<div class="message error">${alerts.error}</div>`;
            return;
        }
        if (alerts.length === 0) {
            adminAlertList.innerHTML = '<div class="message info">No active alerts found.</div>';
            return;
        }
        let html = '';
        alerts.forEach(alert => {
            html += `
                <div class="card">
                    <p class="description" style="border-left-color: #ffc107;">${alert.message}</p>
                    <p class="date-filed" style="text-align: left; margin-top: 0.5rem;">
                        Posted by ${alert.created_by_name} on ${new Date(alert.created_at).toLocaleString()}
                    </p>
                    <div class="card-actions">
                        <button type="button" class="btn btn-danger btn-small" onclick="deleteAlert(${alert.id})">Delete Alert</button>
                    </div>
                </div>`;
        });
        adminAlertList.innerHTML = html;
    } catch (error) {
        console.error('Error loading admin alerts:', error);
        adminAlertList.innerHTML = `<div class="message error">Network error.</div>`;
    }
}

async function deleteAlert(alertId) {
    if (!currentUser || currentUser.role !== 'admin') {
        alert("Unauthorized action.");
        return;
    }
    if (!confirm('Are you sure you want to delete this alert?')) {
        return;
    }
    try {
        const res = await fetch(`${API}/delete_alert`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert_id: alertId, user_role: currentUser.role })
        });
        const out = await res.json();
        if (res.ok) {
            alert(out.message);
            loadAlertsForAdmin();
        } else {
            alert(`Error: ${out.error || "Failed"}`);
        }
    } catch (error) {
        console.error('Error deleting alert:', error);
        alert('Network error.');
    }
}

async function loadAlertsForResident() {
    if (!residentAlertsContainer) return;
    try {
        const res = await fetch(`${API}/get_alerts`);
        const alerts = await res.json();
        if (alerts.error || alerts.length === 0) {
            residentAlertsContainer.innerHTML = '';
            return;
        }
        let html = '<div class="content-header" style="margin-bottom: 1rem;"><h2>📢Important Alerts</h2></div>';
        alerts.forEach(alert => {
            html += `
                <div class="message warning" style="margin-bottom: 1.5rem;">
                    <p style="font-weight: bold;">${alert.message}</p>
                    <p style="font-size: 0.8rem; text-align: right; margin-top: 0.5rem;">
                        Posted on: ${new Date(alert.created_at).toLocaleDateString()}
                    </p>
                </div>`;
        });
        residentAlertsContainer.innerHTML = html;
    } catch (error) {
        console.error('Error loading resident alerts:', error);
    }
}

// --- PAYMENT LOGIC ---

function togglePaymentDescription() {
    const type = document.getElementById('payType').value;
    const descContainer = document.getElementById('payDescriptionContainer');
    const descInput = document.getElementById('payDescription');
    
    if (type === 'Other') {
        descContainer.classList.remove('hidden');
        descInput.setAttribute('required', 'true');
    } else {
        descContainer.classList.add('hidden');
        descInput.removeAttribute('required');
        descInput.value = ''; // Clear value if hidden
    }
}

// Handle Payment Submission
document.getElementById("paymentForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    
    if (!currentUser) return;

    const formData = new FormData();
    formData.append("user_id", currentUser.id);
    formData.append("amount", document.getElementById("payAmount").value);
    formData.append("utr_number", document.getElementById("payUTR").value);
    formData.append("payment_date", document.getElementById("payDate").value);
    
    // Get Type and Description
    const payType = document.getElementById("payType").value;
    formData.append("payment_type", payType);
    
    // Only send description if "Other" is selected, or send empty string
    const payDesc = document.getElementById("payDescription").value;
    formData.append("description", payType === 'Other' ? payDesc : "");
    
    const fileInput = document.getElementById("payScreenshot");
    if (fileInput.files.length > 0) {
        formData.append("screenshot", fileInput.files[0]);
    } else {
        alert("Please upload a screenshot.");
        return;
    }

    const msgDiv = document.getElementById("paymentMsg");
    msgDiv.innerHTML = `<div class="message info">Submitting payment details...</div>`;

    try {
        const res = await fetch(API + "/submit_payment", {
            method: "POST",
            body: formData,
        });

        const out = await res.json();
        if (res.ok) {
            msgDiv.innerHTML = `<div class="message success">${out.message}</div>`;
            document.getElementById("paymentForm").reset();
            togglePaymentDescription();
            // Reset read-only fields after form reset
            document.getElementById('payName').value = currentUser.name;
            document.getElementById('payHouse').value = currentUser.house_number || 'N/A';
            loadMyPayments();
        } else {
            msgDiv.innerHTML = `<div class="message error">${out.error || "Submission failed"}</div>`;
        }
    } catch (error) {
        console.error("Payment error:", error);
        msgDiv.innerHTML = `<div class="message error">Network error.</div>`;
    }
});

// Load Resident Payment History (with Delete button for Pending, Hide for Approved/Rejected)
async function loadMyPayments() {
    const targetElement = document.getElementById("myPaymentList");
    if (!targetElement || !currentUser) return;
    
    targetElement.innerHTML = '<div class="message info">Loading history...</div>';

    try {
        const res = await fetch(`${API}/get_my_payments?user_id=${currentUser.id}`);
        const payments = await res.json();

        if (payments.error) {
            targetElement.innerHTML = `<div class="message error">${payments.error}</div>`;
            return;
        }

        if (payments.length === 0) {
            targetElement.innerHTML = '<div class="message info">No payment history found.</div>';
            return;
        }

        let html = '';
        payments.forEach(pay => {
            // Determine status color class
            let statusClass = 'status-open'; // Default yellow for Pending
            if (pay.status === 'Approved') statusClass = 'status-resolved'; // Green
            if (pay.status === 'Rejected') statusClass = 'status-rejected'; // Red

            let imageHtml = pay.screenshot_path ? `
                <div class="image-attachment">
                    <p style="font-size:0.8rem; margin-bottom:5px;">Proof:</p>
                    <img src="${API}/uploads/${pay.screenshot_path}" 
                         alt="Payment Proof" 
                         class="complaint-image-thumbnail"
                         onclick="window.open('${API}/uploads/${pay.screenshot_path}', '_blank')">
                </div>
            ` : '';
            
            // --- UPDATED BUTTON LOGIC ---
            let actionBtnHtml = '';
            
            if (pay.status === 'Pending') {
                // Allow Hard Delete if Pending
                actionBtnHtml = `
                    <button type="button" class="btn btn-danger btn-small" 
                            style="margin-top:10px; width:100%;"
                            onclick="deletePayment(${pay.id})">
                        Delete Request
                    </button>
                `;
            } else if (pay.status === 'Approved' || pay.status === 'Rejected') {
                // Allow "Hide" (Soft Delete) if Approved or Rejected
                actionBtnHtml = `
                    <button type="button" class="btn btn-warning btn-small" 
                            style="margin-top:10px; width:100%; background: #6c757d; border-color: #6c757d; color: white;"
                            onclick="hidePayment(${pay.id})">
                        Remove from History
                    </button>
                `;
            }

            let typeDisplay = `<strong>Type:</strong> ${pay.payment_type || 'Maintenance'}`;
            if (pay.payment_type === 'Other' && pay.description) {
                typeDisplay += `<br><strong>Note:</strong> ${pay.description}`;
            }

            html += `
                <div class="card complaint-card ${statusClass}">
                    <h4>₹${pay.amount}</h4>
                    <p>${typeDisplay}</p>
                    <p><strong>UTR:</strong> ${pay.utr_number}</p>
                    <p><strong>Date Paid:</strong> ${new Date(pay.payment_date).toLocaleString()}</p>
                    <p><strong>Status:</strong> <span class="badge status-badge">${pay.status}</span></p>
                    ${imageHtml}
                    <div class="date-filed" style="margin-top:1rem;">
                        Submitted on: ${new Date(pay.created_at).toLocaleDateString()}
                    </div>
                    ${actionBtnHtml}
                </div>
            `;
        });
        targetElement.innerHTML = html;

    } catch (error) {
        console.error("Load payments error:", error);
        targetElement.innerHTML = `<div class="message error">Network error.</div>`;
    }
}

// Admin: Load All Society Payments
async function loadAllSocietyPayments() {
    const targetElement = document.getElementById("adminPaymentList");
    if (!targetElement) return;
    
    targetElement.innerHTML = '<div class="message info">Loading society payments...</div>';

    if (!currentUser || currentUser.role !== 'admin') {
        targetElement.innerHTML = `<div class="message error">Unauthorized.</div>`;
        return;
    }

    try {
        const res = await fetch(`${API}/get_all_payments`);
        const payments = await res.json();

        if (payments.error) {
            targetElement.innerHTML = `<div class="message error">${payments.error}</div>`;
            return;
        }

        if (payments.length === 0) {
            targetElement.innerHTML = '<div class="message info">No payments submitted yet.</div>';
            return;
        }

        let html = '';
        payments.forEach(pay => {
            let statusClass = 'status-open';
            if (pay.status === 'Approved') statusClass = 'status-resolved';
            if (pay.status === 'Rejected') statusClass = 'status-rejected';

            let imageHtml = pay.screenshot_path ? `
                <div class="image-attachment">
                    <p style="font-size:0.8rem;">Proof:</p>
                    <img src="${API}/uploads/${pay.screenshot_path}" 
                         class="complaint-image-thumbnail"
                         onclick="window.open('${API}/uploads/${pay.screenshot_path}', '_blank')">
                </div>
            ` : '<p style="color:#888; font-size:0.9rem;">No screenshot attached</p>';

            // Admin Actions
            let actionButtons = '';
            if (pay.status === 'Pending') {
                actionButtons = `
                    <div class="card-actions">
                        <button class="btn btn-success btn-small" onclick="updatePaymentStatus(${pay.id}, 'Approved')">Approve</button>
                        <button class="btn btn-danger btn-small" onclick="updatePaymentStatus(${pay.id}, 'Rejected')">Reject</button>
                    </div>
                `;
            } else {
                 actionButtons = `
                    <div class="card-actions">
                        <span style="font-size:0.9rem; color:#666;">Processed as <strong>${pay.status}</strong></span>
                        <button class="btn btn-warning btn-small" style="margin-left:auto;" onclick="updatePaymentStatus(${pay.id}, 'Pending')">Edit</button>
                    </div>
                 `;
            }

            let typeDisplay = `<strong>Type:</strong> ${pay.payment_type || 'Maintenance'}`;
            if (pay.payment_type === 'Other' && pay.description) {
                typeDisplay += `<br><strong>Note:</strong> ${pay.description}`;
            }

            html += `
                <div class="card complaint-card ${statusClass}">
                    <h4>${pay.user_name} (House: ${pay.house_number || 'N/A'})</h4>
                    <p><strong>Amount:</strong> ₹${pay.amount}</p>
                    <p>${typeDisplay}</p>
                    <p><strong>UTR:</strong> ${pay.utr_number}</p>
                    <p><strong>Payment Date:</strong> ${new Date(pay.payment_date).toLocaleDateString()}</p>
                    ${imageHtml}
                    ${actionButtons}
                    <div class="date-filed" style="margin-top:0.5rem;">
                        Submitted: ${new Date(pay.created_at).toLocaleString()}
                    </div>
                </div>
            `;
        });
        targetElement.innerHTML = html;

    } catch (error) {
        console.error("Load all payments error:", error);
        targetElement.innerHTML = `<div class="message error">Network error.</div>`;
    }
}

async function updatePaymentStatus(paymentId, status) {
    if (!confirm(`Mark this payment as ${status}?`)) return;

    try {
        const res = await fetch(`${API}/update_payment_status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payment_id: paymentId, status: status })
        });
        
        const out = await res.json();
        if (res.ok) {
            loadAllSocietyPayments(); 
        } else {
            alert(`Error: ${out.error}`);
        }
    } catch (error) {
        console.error("Update payment error:", error);
        alert("Network error.");
    }
}

async function deletePayment(paymentId) {
    if (!confirm("Are you sure you want to delete this payment request?")) return;

    try {
        const res = await fetch(`${API}/delete_payment`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                payment_id: paymentId, 
                user_id: currentUser.id,
                user_role: currentUser.role
            })
        });

        const out = await res.json();
        if (res.ok) {
            alert("Payment deleted successfully.");
            loadMyPayments(); 
        } else {
            alert(`Error: ${out.error}`);
        }
    } catch (error) {
        console.error("Delete payment error:", error);
        alert("Network error.");
    }
}

async function hidePayment(paymentId) {
    if (!confirm("Remove this payment from your history? (This cannot be undone)")) return;

    try {
        const res = await fetch(`${API}/hide_payment`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                payment_id: paymentId, 
                user_id: currentUser.id
            })
        });

        const out = await res.json();
        if (res.ok) {
            loadMyPayments(); 
        } else {
            alert(`Error: ${out.error}`);
        }
    } catch (error) {
        console.error("Hide payment error:", error);
        alert("Network error.");
    }
}

// AI Search/Analysis Placeholder
aiSearchButton?.addEventListener("click", () => {
    const query = aiInputArea.value.trim();
    const responseArea = document.getElementById('aiResponseArea');
    responseArea.style.display = 'block';
    
    if (query) {
        responseArea.innerHTML = `<div class="message info">
            Searching AI for: <strong>${query}</strong>... <br>
            *To enable this feature, you will need to implement a new endpoint in your Python backend (e.g., \`/ai_complaint_query\`) that calls an actual AI service and returns the analyzed data.*
        </div>`;
    } else {
        responseArea.innerHTML = `<div class="message error">Please type your search query or AI command.</div>`;
    }
});


// Initial check for logged-in user
document.addEventListener("DOMContentLoaded", () => {
  const storedUser = localStorage.getItem('currentUser');
  if (storedUser) {
    try {
      currentUser = JSON.parse(storedUser);
      showHome();
      setTimeout(showDashboard, 0); 
    } catch (e) {
        console.error("Error parsing stored user:", e);
        localStorage.removeItem('currentUser');
        showHome();
    }
  } else {
    showHome();
  }
});

document.addEventListener("DOMContentLoaded", () => {
    document.querySelector('#viewPollsBtn')?.classList.add('active');
});

// Password Visibility Toggle
function togglePassword(inputId, btn) {
    const input = document.getElementById(inputId);
    if (input.type === "password") {
        input.type = "text";
        btn.textContent = "🙈"; 
    } else {
        input.type = "password";
        btn.textContent = "👁️";
    }
}