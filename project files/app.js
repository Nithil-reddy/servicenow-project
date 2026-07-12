import { runSecurityTests } from './test_suite.js';

// ============================================================================
// SYSTEM STATE & DATABASE DEFINITIONS (LocalStorage backed)
// ============================================================================

class ServiceNowSystem {
  constructor() {
    this.currentUser = 'admin'; // default context

    // 1. System Users
    this.users = [
      { id: 'admin.user', username: 'admin', firstName: 'System', lastName: 'Administrator', email: 'admin@company.com', roles: ['admin'], groups: [] },
      { id: 'alice.pm', username: 'alice', firstName: 'Alice', lastName: 'ProjectManager', email: 'alice.pm@company.com', roles: ['u_project_manager'], groups: ['Project Managers'] },
      { id: 'bob.member', username: 'bob', firstName: 'Bob', lastName: 'TeamMember', email: 'bob.member@company.com', roles: ['u_team_member'], groups: ['Project Team Members'] },
      { id: 'guest.user', username: 'guest', firstName: 'Guest', lastName: 'User', email: 'guest@company.com', roles: [], groups: [] }
    ];

    // 2. System Groups
    this.groups = [
      { id: 'grp_pm', name: 'Project Managers', description: 'Group for project managers and planners.', roles: ['u_project_manager'], members: ['alice.pm'] },
      { id: 'grp_tm', name: 'Project Team Members', description: 'Group for general team engineers and assignees.', roles: ['u_team_member'], members: ['bob.member'] }
    ];

    // 3. System Roles
    this.roles = [
      { id: 'role_admin', name: 'admin', description: 'System Administrator with unrestricted access.' },
      { id: 'role_pm', name: 'u_project_manager', description: 'Custom project manager capability role.' },
      { id: 'role_tm', name: 'u_team_member', description: 'Custom task fulfiller capability role.' }
    ];

    // Load dynamic DB tables or write defaults
    this.initDatabase();

    // 4. System Emails (sys_email log)
    this.notifications = JSON.parse(localStorage.getItem('sn_notifications')) || [];
    
    // 5. Flow Run statistics
    this.flowRuns = parseInt(localStorage.getItem('sn_flow_runs')) || 0;
    this.escalations = parseInt(localStorage.getItem('sn_escalations')) || 0;

    // View tracking
    this.currentView = 'projects';
    this.searchQuery = '';
  }

  initDatabase() {
    // Projects table (u_project)
    const defaultProjects = [
      { id: 'proj01', number: 'PRJ0010001', name: 'Jupiter Core Infrastructure', manager: 'alice.pm', status: 'Active', description: 'Deployment of core private cloud hypervisors and fiber link configurations.' },
      { id: 'proj02', number: 'PRJ0010002', name: 'Apollo Identity & Access Security', manager: 'alice.pm', status: 'Planning', description: 'Hardening credential stores and enabling single-sign-on (SSO) globally.' }
    ];

    // Tasks table (u_project_task extending task)
    const defaultTasks = [
      { id: 'task01', number: 'PRJTASK0010001', short_description: 'Configure firewall switches', u_project: 'proj01', assigned_to: 'bob.member', state: 'Work in Progress', u_escalated: false, priority: 'p3', u_due_date: this.getRelativeDate(2), description: 'Open ports 443, 80, and 22 on the new server racks to accommodate hypervisor communication lines.' },
      { id: 'task02', number: 'PRJTASK0010002', short_description: 'Audit LDAP sync configurations', u_project: 'proj02', assigned_to: 'bob.member', state: 'Open', u_escalated: false, priority: 'p4', u_due_date: this.getRelativeDate(5), description: 'Audit directory schemas to confirm project users can log in cleanly.' },
      { id: 'task03', number: 'PRJTASK0010003', short_description: 'Update hardware bios', u_project: 'proj01', assigned_to: '', state: 'Open', u_escalated: false, priority: 'p4', u_due_date: this.getRelativeDate(-1), description: 'Firmware upgrades are required for critical hypervisors. (Past due for SLA simulation)' }
    ];

    this.projects = JSON.parse(localStorage.getItem('sn_projects')) || defaultProjects;
    this.tasks = JSON.parse(localStorage.getItem('sn_tasks')) || defaultTasks;
  }

  saveDatabase() {
    localStorage.setItem('sn_projects', JSON.stringify(this.projects));
    localStorage.setItem('sn_tasks', JSON.stringify(this.tasks));
    localStorage.setItem('sn_notifications', JSON.stringify(this.notifications));
    localStorage.setItem('sn_flow_runs', this.flowRuns.toString());
    localStorage.setItem('sn_escalations', this.escalations.toString());
  }

  getRelativeDate(daysOffset) {
    const d = new Date();
    d.setDate(d.getDate() + daysOffset);
    return d.toISOString().slice(0, 16); // return datetime-local friendly format
  }

  // ============================================================================
  // SECURITY & ACCESS CONTROL LIST (ACL) EVALUATION ENGINE
  // ============================================================================

  /**
   * Evaluates ACL rules on a table/operation for the active user context
   */
  hasAccess(table, operation, record = null) {
    return this.hasAccessForUser(this.currentUser, table, operation, record);
  }

  /**
   * Core security rules matching ServiceNow ACLs
   */
  hasAccessForUser(username, table, operation, record = null) {
    const user = this.users.find(u => u.username === username);
    if (!user) return false;

    // Admin override (unrestricted access)
    if (user.roles.includes('admin')) {
      return true;
    }

    // Guest has no access to tables
    if (user.roles.includes('guest') || user.roles.length === 0) {
      return false;
    }

    // 1. Project Table ACLs (u_project)
    if (table === 'u_project') {
      // Create, Read, Write, Delete are ONLY for Project Managers
      return user.roles.includes('u_project_manager');
    }

    // 2. Task Table ACLs (u_project_task)
    if (table === 'u_project_task') {
      // Create and Delete are ONLY for Project Managers
      if (operation === 'create' || operation === 'delete') {
        return user.roles.includes('u_project_manager');
      }

      // Read and Write are for Project Managers OR assigned Team Members
      if (operation === 'read' || operation === 'write') {
        if (user.roles.includes('u_project_manager')) {
          return true;
        }
        if (user.roles.includes('u_team_member')) {
          // Row-level check: Assigned user must match the evaluating user's ID
          if (record && record.assigned_to === user.id) {
            return true;
          }
          // If checking table access generally without record context (e.g. for listing tasks)
          if (!record) {
            return true;
          }
        }
      }
    }

    // 3. Admin Tables Configuration ACLs
    if (['sys_user', 'sys_user_group', 'sys_user_role', 'sys_security_acl'].includes(table)) {
      return user.roles.includes('admin');
    }

    // 4. Flows Overview ACLs
    if (table === 'sys_hub_flow') {
      return user.roles.includes('admin') || user.roles.includes('u_project_manager');
    }

    return false;
  }
}

// Instantiate the system core
const system = new ServiceNowSystem();

// ============================================================================
// WORKFLOW LOGGING & ACTIONS
// ============================================================================

function sysLog(text, type = 'info') {
  const container = document.getElementById('consoleLogs');
  if (!container) return;

  const time = new Date().toLocaleTimeString();
  const logDiv = document.createElement('div');
  logDiv.className = 'log-entry';
  logDiv.innerHTML = `
    <span class="log-time">[${time}]</span>
    <span class="log-text ${type}">${text}</span>
  `;
  container.appendChild(logDiv);
  container.scrollTop = container.scrollHeight;
}

/**
   * Simulates ServiceNow Flow Designer execution triggers
   */
system.simulateWorkflowTrigger = function(taskRecord) {
  sysLog(`[Flow Trigger] u_project_task_assignment_escalation_flow triggered (INSERT_ACTION)`, 'trigger');
  
  system.flowRuns++;
  
  // Create a copy of the task to avoid reference issues
  const task = { ...taskRecord };

  // Action 1: Auto-assignment
  if (!task.assigned_to) {
    // Find Bob's ID
    const bob = system.users.find(u => u.username === 'bob');
    if (bob) {
      task.assigned_to = bob.id;
      sysLog(`[Action 1] Auto-Assign: Field 'assigned_to' empty. Assigned to Bob TeamMember (${bob.id})`, 'success');
    }
  }

  // Action 2: Trigger state change
  if (task.state === 'Open') {
    task.state = 'Work in Progress';
    sysLog(`[Action 2] State Change: Task initialized. Automatically transitioned to 'Work in Progress'`, 'success');
  }

  // Action 3: Generate assignment notification
  const assignee = system.users.find(u => u.id === task.assigned_to);
  const parentProj = system.projects.find(p => p.id === task.u_project);
  if (assignee) {
    const email = {
      id: 'email_' + Date.now(),
      sent: new Date().toLocaleTimeString(),
      recipient: assignee.email,
      subject: `Task Assigned: ${task.short_description} (${task.number})`,
      body: `Hello ${assignee.firstName},\n\nYou have been assigned to task ${task.number} under Project: "${parentProj ? parentProj.name : 'Unknown'}".\n\nShort Description: ${task.short_description}\nState: ${task.state}\nDue Date: ${task.u_due_date || 'N/A'}\n\nPlease begin working on this item. Log updates in the Project Task workspace.`
    };
    system.notifications.unshift(email);
    sysLog(`[Action 3] Email Queue: Created notification record (sys_email) for ${assignee.email}`, 'success');
    triggerBellAlert();
  }

  sysLog(`[Flow Completed] Workflow successfully exited.`, 'info');
  system.saveDatabase();
  updateWorkflowMetrics();
  return task;
};

/**
 * Runs SLA overdue evaluation across all task records
 */
system.evaluateSlaBreaches = function() {
  sysLog(`[SLA Evaluation Job] Commencing automated SLA checking...`, 'trigger');
  const now = new Date();
  let breachesFound = 0;

  system.tasks.forEach(task => {
    // Check if task is overdue, not closed, and not already escalated
    const isClosed = ['Closed Complete', 'Closed Skipped'].includes(task.state);
    if (task.u_due_date && !isClosed && !task.u_escalated) {
      const dueDate = new Date(task.u_due_date);
      if (now > dueDate) {
        // SLA Breached! Escalating
        task.u_escalated = true;
        task.priority = 'p1'; // Set to 1 - Critical
        system.escalations++;
        breachesFound++;

        sysLog(`[SLA Breach] Task ${task.number} ("${task.short_description}") has breached due date. Escalating priority!`, 'warn');

        // Notify Project Manager (Alice)
        const pm = system.users.find(u => u.username === 'alice');
        const assignee = system.users.find(u => u.id === task.assigned_to);
        if (pm) {
          const escalationEmail = {
            id: 'email_esc_' + Date.now() + '_' + task.id,
            sent: new Date().toLocaleTimeString(),
            recipient: pm.email,
            subject: `ESCALATION: Overdue Task Notification - ${task.number}`,
            body: `Hi Alice,\n\nTask ${task.number} ("${task.short_description}") has exceeded its due date (${task.u_due_date}) without completion.\n\nAssigned To: ${assignee ? assignee.firstName + ' ' + assignee.lastName : 'Unassigned'}\nCurrent State: ${task.state}\n\nThe task priority has been raised to 1 - Critical. Please review this record and intervene.`,
          };
          system.notifications.unshift(escalationEmail);
          sysLog(`[Escalation Action] Email Alert: Dispatched manager alert to ${pm.email}`, 'warn');
          triggerBellAlert();
        }
      }
    }
  });

  sysLog(`[SLA Evaluation Job] Finished. Evaluated ${system.tasks.length} tasks. Escalated ${breachesFound} overdue records.`, breachesFound > 0 ? 'warn' : 'success');
  system.saveDatabase();
  updateWorkflowMetrics();
  render();
};

// ============================================================================
// UI BINDING & INTERACTION LOGIC
// ============================================================================

// Bell notifications alert helpers
function triggerBellAlert() {
  const badge = document.getElementById('notifBadge');
  if (badge) badge.classList.add('active');
}

function updateWorkflowMetrics() {
  const mRuns = document.getElementById('metricRuns');
  const mNotifs = document.getElementById('metricNotifs');
  const mEscalations = document.getElementById('metricEscalations');

  if (mRuns) mRuns.innerText = system.flowRuns;
  if (mNotifs) mNotifs.innerText = system.notifications.length;
  if (mEscalations) mEscalations.innerText = system.escalations;
}

// Impersonation change handler
document.getElementById('impersonateSelect').addEventListener('change', (e) => {
  const selectedUser = e.target.value;
  system.currentUser = selectedUser;
  
  const userObj = system.users.find(u => u.username === selectedUser);
  sysLog(`[Session Management] Impersonating User Context: ${userObj.firstName} ${userObj.lastName} (Roles: [${userObj.roles.join(', ') || 'none'}])`, 'info');

  // Update Footer Profile Widget
  const avatar = document.getElementById('footerAvatar');
  const dispName = document.getElementById('footerUserName');
  const dispRole = document.getElementById('footerUserRole');
  
  if (avatar) avatar.innerText = userObj.firstName.substring(0,2).toUpperCase();
  if (dispName) dispName.innerText = `${userObj.firstName} ${userObj.lastName}`;
  
  let roleDesc = "Guest User (No Roles)";
  if (userObj.roles.includes('admin')) roleDesc = "Administrator (Full Access)";
  else if (userObj.roles.includes('u_project_manager')) roleDesc = "Project Manager (project_manager)";
  else if (userObj.roles.includes('u_team_member')) roleDesc = "Team Member (team_member)";
  if (dispRole) dispRole.innerText = roleDesc;

  // Render layout according to permissions
  toggleNavAvailability();
  
  // Redirect to self-service views if access was revoked from admin panel
  if (['users', 'groups', 'roles', 'acls'].includes(system.currentView) && !userObj.roles.includes('admin')) {
    system.currentView = 'tasks';
    setActiveNavItem('tasks');
  }

  render();
});

function toggleNavAvailability() {
  const isAdmin = system.hasAccess('sys_user', 'read');
  const adminSection = document.getElementById('adminNavSection');
  
  if (adminSection) {
    if (isAdmin) {
      adminSection.classList.remove('d-none');
    } else {
      adminSection.classList.add('d-none');
    }
  }

  // Display security badge warnings on navigations if blocked
  const projBadge = document.getElementById('projectsAclBadge');
  if (projBadge) {
    if (!system.hasAccess('u_project', 'read')) {
      projBadge.classList.remove('d-none');
    } else {
      projBadge.classList.add('d-none');
    }
  }
}

// Navigation items click handling
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    const target = item.getAttribute('data-target');
    system.currentView = target;
    
    // Highlight sidebar active item
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');

    // Breadcrumbs setting
    const breadcrumbSec = document.getElementById('breadcrumbSection');
    const breadcrumbPage = document.getElementById('breadcrumbPage');
    const mainTitle = document.getElementById('mainPageTitle');
    
    let sec = "Project Management";
    let pg = "Projects";
    
    if (['users', 'groups', 'roles', 'acls', 'flows'].includes(target)) {
      sec = "System Administration";
      pg = item.querySelector('span').innerText;
    } else if (target === 'xml-preview') {
      sec = "Developer Tools";
      pg = "Update Set XML";
    } else {
      pg = item.querySelector('span').innerText;
    }

    if (breadcrumbSec) breadcrumbSec.innerText = sec;
    if (breadcrumbPage) breadcrumbPage.innerText = pg;
    if (mainTitle) mainTitle.innerText = pg;

    render();
  });
});

function setActiveNavItem(targetView) {
  document.querySelectorAll('.nav-item').forEach(item => {
    if (item.getAttribute('data-target') === targetView) {
      item.classList.add('active');
      
      const breadcrumbPage = document.getElementById('breadcrumbPage');
      const mainTitle = document.getElementById('mainPageTitle');
      if (breadcrumbPage) breadcrumbPage.innerText = item.querySelector('span').innerText;
      if (mainTitle) mainTitle.innerText = item.querySelector('span').innerText;
    } else {
      item.classList.remove('active');
    }
  });
}

// Navigator Filter Filter-As-You-Type
document.getElementById('navFilter').addEventListener('input', (e) => {
  const query = e.target.value.toLowerCase();
  document.querySelectorAll('.nav-item').forEach(item => {
    const label = item.querySelector('span').innerText.toLowerCase();
    if (label.includes(query)) {
      item.classList.remove('d-none');
    } else {
      item.classList.add('d-none');
    }
  });
  
  // Hide empty sections
  document.querySelectorAll('.nav-section').forEach(section => {
    const visibleItems = section.querySelectorAll('.nav-item:not(.d-none)');
    if (visibleItems.length === 0) {
      section.classList.add('d-none');
    } else {
      section.classList.remove('d-none');
    }
  });
});

// Notifications Drawer Toggle
document.getElementById('notifBellBtn').addEventListener('click', (e) => {
  e.stopPropagation();
  const slider = document.getElementById('notifSlider');
  const badge = document.getElementById('notifBadge');
  slider.classList.toggle('active');
  if (badge) badge.classList.remove('active');
});

document.addEventListener('click', () => {
  const slider = document.getElementById('notifSlider');
  if (slider) slider.classList.remove('active');
});

document.getElementById('notifSlider').addEventListener('click', (e) => {
  e.stopPropagation(); // prevent closing
});

document.getElementById('clearNotifsBtn').addEventListener('click', () => {
  system.notifications = [];
  system.saveDatabase();
  sysLog("[Notification Service] Cleared mail queue (sys_email).", "info");
  renderNotifications();
});

// SLA Check Job Execution Buttons
document.getElementById('triggerSlaJobBtn').addEventListener('click', () => system.evaluateSlaBreaches());
document.getElementById('triggerSlaWorkflowPageBtn').addEventListener('click', () => system.evaluateSlaBreaches());

// Clear Logs Console
document.getElementById('clearLogsBtn').addEventListener('click', () => {
  const logs = document.getElementById('consoleLogs');
  if (logs) logs.innerHTML = `<div class="log-entry"><span class="log-time">[System]</span> <span class="log-text info">Logs cleared by ${system.currentUser}. Console active.</span></div>`;
});

// Copy XML button
document.getElementById('copyXmlBtn').addEventListener('click', () => {
  const codeText = document.getElementById('xmlViewer').innerText;
  navigator.clipboard.writeText(codeText).then(() => {
    sysLog("[Developer Suite] Update Set XML copied to clipboard successfully.", "success");
    alert("XML content copied to clipboard!");
  }).catch(err => {
    sysLog("[Developer Suite] Failed to copy XML: " + err, "error");
  });
});

// Search filters on tables
document.getElementById('searchProjects').addEventListener('input', (e) => {
  system.searchQuery = e.target.value.toLowerCase();
  renderProjectsList();
});
document.getElementById('searchTasks').addEventListener('input', (e) => {
  system.searchQuery = e.target.value.toLowerCase();
  renderTasksList();
});
document.getElementById('searchAdmin').addEventListener('input', (e) => {
  system.searchQuery = e.target.value.toLowerCase();
  renderAdminTableList();
});

// Action button: create new project or task depending on view
document.getElementById('actionBtn').addEventListener('click', () => {
  if (system.currentView === 'projects') {
    if (!system.hasAccess('u_project', 'create')) {
      alert("Security constraint error: You do not have the required roles to create project records.");
      sysLog("[ACL Enforced] Blocked attempt to CREATE record in u_project (403 Forbidden)", "error");
      return;
    }
    openProjectModal();
  } else if (system.currentView === 'tasks') {
    if (!system.hasAccess('u_project_task', 'create')) {
      alert("Security constraint error: Only project managers can create task records.");
      sysLog("[ACL Enforced] Blocked attempt to CREATE record in u_project_task (403 Forbidden)", "error");
      return;
    }
    openTaskModal();
  }
});

// ============================================================================
// MAIN RENDERING ROUTINES
// ============================================================================

function render() {
  // Hide all views first
  document.getElementById('accessDeniedState').classList.add('d-none');
  document.getElementById('projectsListView').classList.add('d-none');
  document.getElementById('tasksListView').classList.add('d-none');
  document.getElementById('adminListView').classList.add('d-none');
  document.getElementById('flowDesignerView').classList.add('d-none');
  document.getElementById('xmlPreviewView').classList.add('d-none');
  
  // Show / Hide action button
  const actionBtn = document.getElementById('actionBtn');
  if (['projects', 'tasks'].includes(system.currentView)) {
    actionBtn.classList.remove('d-none');
    
    // Check permission to determine if button should be disabled
    const hasCreatePerm = (system.currentView === 'projects') ? 
                          system.hasAccess('u_project', 'create') : 
                          system.hasAccess('u_project_task', 'create');
                          
    actionBtn.disabled = !hasCreatePerm;
    actionBtn.style.opacity = hasCreatePerm ? "1" : "0.5";
  } else {
    actionBtn.classList.add('d-none');
  }

  // 1. Evaluate general view-level read ACL
  let hasReadAccess = true;
  if (system.currentView === 'projects') {
    hasReadAccess = system.hasAccess('u_project', 'read');
  } else if (system.currentView === 'tasks') {
    hasReadAccess = system.hasAccess('u_project_task', 'read');
  } else if (['users', 'groups', 'roles', 'acls'].includes(system.currentView)) {
    hasReadAccess = system.hasAccess(system.currentView === 'acls' ? 'sys_security_acl' : 'sys_user', 'read');
  } else if (system.currentView === 'xml-preview') {
    // Shared between PM and Admin
    hasReadAccess = system.hasAccess('u_project', 'read');
  }
  
  if (!hasReadAccess) {
    document.getElementById('accessDeniedState').classList.remove('d-none');
    return;
  }

  // Render appropriate view
  switch(system.currentView) {
    case 'projects':
      document.getElementById('projectsListView').classList.remove('d-none');
      renderProjectsList();
      break;
    case 'tasks':
      document.getElementById('tasksListView').classList.remove('d-none');
      renderTasksList();
      break;
    case 'users':
    case 'groups':
    case 'roles':
    case 'acls':
      document.getElementById('adminListView').classList.remove('d-none');
      renderAdminTableList();
      break;
    case 'flows':
      document.getElementById('flowDesignerView').classList.remove('d-none');
      break;
    case 'xml-preview':
      document.getElementById('xmlPreviewView').classList.remove('d-none');
      renderXmlPreview();
      break;
  }

  renderNotifications();
  updateWorkflowMetrics();
}

// 1. Projects List Render
function renderProjectsList() {
  const tbody = document.getElementById('projectsTableBody');
  tbody.innerHTML = '';
  
  // Filter search
  const filtered = system.projects.filter(p => 
    p.number.toLowerCase().includes(system.searchQuery) ||
    p.name.toLowerCase().includes(system.searchQuery) ||
    p.description.toLowerCase().includes(system.searchQuery)
  );

  document.getElementById('projectsCount').innerText = `Showing ${filtered.length} of ${system.projects.length} records`;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No records found.</td></tr>`;
    return;
  }

  // Check write/delete permissions generally for list row actions
  const hasWrite = system.hasAccess('u_project', 'write');
  const hasDelete = system.hasAccess('u_project', 'delete');

  filtered.forEach(p => {
    const manager = system.users.find(u => u.id === p.manager);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="monospace" style="color: var(--primary); font-weight: 600;">${p.number}</td>
      <td style="font-weight: 500;">${escapeHtml(p.name)}</td>
      <td>${manager ? manager.firstName + ' ' + manager.lastName : 'Unassigned'}</td>
      <td><span class="badge-status ${p.status.toLowerCase()}">${p.status}</span></td>
      <td style="max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text-muted);">${escapeHtml(p.description)}</td>
      <td>
        <div class="row-actions">
          <button class="icon-btn edit-btn" onclick="window.editProject('${p.id}')" title="${hasWrite ? 'Edit Record' : 'View Details'}">
            <i class="fa-solid ${hasWrite ? 'fa-pencil' : 'fa-eye'}"></i>
          </button>
          <button class="icon-btn delete-btn ${hasDelete ? '' : 'd-none'}" onclick="window.deleteProject('${p.id}')" title="Delete Record">
            <i class="fa-solid fa-trash"></i>
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// 2. Tasks List Render
function renderTasksList() {
  const tbody = document.getElementById('tasksTableBody');
  tbody.innerHTML = '';

  // Get matching user role
  const userObj = system.users.find(u => u.username === system.currentUser);

  // Apply row-level ACL filters:
  // Admin sees all, PM sees all, Bob (Team Member) only sees tasks assigned to him!
  const permittedTasks = system.tasks.filter(task => {
    return system.hasAccess('u_project_task', 'read', task);
  });

  const filtered = permittedTasks.filter(t => 
    t.number.toLowerCase().includes(system.searchQuery) ||
    t.short_description.toLowerCase().includes(system.searchQuery) ||
    t.description.toLowerCase().includes(system.searchQuery)
  );

  document.getElementById('tasksCount').innerText = `Showing ${filtered.length} of ${permittedTasks.length} accessible records`;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No task records found.</td></tr>`;
    return;
  }

  filtered.forEach(t => {
    const parentProj = system.projects.find(p => p.id === t.u_project);
    const assignee = system.users.find(u => u.id === t.assigned_to);
    
    // Check write/delete permissions for this specific record
    const hasWrite = system.hasAccess('u_project_task', 'write', t);
    const hasDelete = system.hasAccess('u_project_task', 'delete', t);
    
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="monospace" style="color: var(--primary); font-weight: 600;">${t.number}</td>
      <td style="font-weight: 500;">${escapeHtml(t.short_description)}</td>
      <td>${parentProj ? escapeHtml(parentProj.name) : 'None'}</td>
      <td><i class="fa-solid fa-user" style="font-size:11px; margin-right: 6px; color: var(--text-muted);"></i>${assignee ? assignee.firstName + ' ' + assignee.lastName : '<span style="color: var(--warning); font-style: italic;">Unassigned</span>'}</td>
      <td><span class="badge-status ${t.state.toLowerCase().replace(/\s+/g, '-')}">${t.state}</span></td>
      <td>
        <span style="color: ${t.u_escalated ? 'var(--danger)' : 'var(--text-muted)'}; font-size:16px;">
          <i class="fa-solid ${t.u_escalated ? 'fa-circle-exclamation' : 'fa-circle-check'}"></i>
        </span>
      </td>
      <td class="monospace" style="font-size: 11px; color: var(--text-muted);">${t.u_due_date ? t.u_due_date.replace('T', ' ') : 'N/A'}</td>
      <td>
        <div class="row-actions">
          <button class="icon-btn edit-btn" onclick="window.editTask('${t.id}')" title="${hasWrite ? 'Edit Record' : 'View Details'}">
            <i class="fa-solid ${hasWrite ? 'fa-pencil' : 'fa-eye'}"></i>
          </button>
          <button class="icon-btn delete-btn ${hasDelete ? '' : 'd-none'}" onclick="window.deleteTask('${t.id}')" title="Delete Record">
            <i class="fa-solid fa-trash"></i>
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// 3. Admin configuration table rendering
function renderAdminTableList() {
  const header = document.getElementById('adminTableHeader');
  const tbody = document.getElementById('adminTableBody');
  header.innerHTML = '';
  tbody.innerHTML = '';

  let records = [];
  let cols = [];

  if (system.currentView === 'users') {
    records = system.users;
    cols = ['ID', 'Username', 'First Name', 'Last Name', 'Email', 'Roles', 'Groups'];
    
    // Header
    const tr = document.createElement('tr');
    cols.forEach(c => tr.innerHTML += `<th>${c}</th>`);
    header.appendChild(tr);

    // Filter
    const filtered = records.filter(r => r.username.includes(system.searchQuery) || r.email.includes(system.searchQuery));
    document.getElementById('adminCount').innerText = `Showing ${filtered.length} users`;

    // Body
    filtered.forEach(u => {
      const rTr = document.createElement('tr');
      rTr.innerHTML = `
        <td class="monospace">${u.id}</td>
        <td style="font-weight: 500; color: var(--primary);">${u.username}</td>
        <td>${u.firstName}</td>
        <td>${u.lastName}</td>
        <td>${u.email}</td>
        <td><code class="monospace" style="color: var(--warning);">${u.roles.join(', ') || 'none'}</code></td>
        <td>${u.groups.join(', ') || 'none'}</td>
      `;
      tbody.appendChild(rTr);
    });

  } else if (system.currentView === 'groups') {
    records = system.groups;
    cols = ['ID', 'Group Name', 'Description', 'Roles Inherited', 'Members'];
    
    const tr = document.createElement('tr');
    cols.forEach(c => tr.innerHTML += `<th>${c}</th>`);
    header.appendChild(tr);

    const filtered = records.filter(r => r.name.toLowerCase().includes(system.searchQuery));
    document.getElementById('adminCount').innerText = `Showing ${filtered.length} groups`;

    filtered.forEach(g => {
      const rTr = document.createElement('tr');
      rTr.innerHTML = `
        <td class="monospace">${g.id}</td>
        <td style="font-weight: 600; color: var(--primary);">${g.name}</td>
        <td>${g.description}</td>
        <td><code class="monospace" style="color: var(--warning);">${g.roles.join(', ')}</code></td>
        <td>${g.members.join(', ')}</td>
      `;
      tbody.appendChild(rTr);
    });

  } else if (system.currentView === 'roles') {
    records = system.roles;
    cols = ['ID', 'Role Name', 'Description'];
    
    const tr = document.createElement('tr');
    cols.forEach(c => tr.innerHTML += `<th>${c}</th>`);
    header.appendChild(tr);

    const filtered = records.filter(r => r.name.toLowerCase().includes(system.searchQuery));
    document.getElementById('adminCount').innerText = `Showing ${filtered.length} roles`;

    filtered.forEach(r => {
      const rTr = document.createElement('tr');
      rTr.innerHTML = `
        <td class="monospace">${r.id}</td>
        <td style="font-weight: 600; color: var(--warning);">${r.name}</td>
        <td>${r.description}</td>
      `;
      tbody.appendChild(rTr);
    });

  } else if (system.currentView === 'acls') {
    // Generate list representing defined ACLs
    const acls = [
      { table: 'u_project', operation: 'create', role: 'u_project_manager', condition: 'None' },
      { table: 'u_project', operation: 'read', role: 'u_project_manager', condition: 'None' },
      { table: 'u_project', operation: 'write', role: 'u_project_manager', condition: 'None' },
      { table: 'u_project', operation: 'delete', role: 'u_project_manager', condition: 'None' },
      { table: 'u_project_task', operation: 'create', role: 'u_project_manager', condition: 'None' },
      { table: 'u_project_task', operation: 'delete', role: 'u_project_manager', condition: 'None' },
      { table: 'u_project_task', operation: 'read', role: 'u_project_manager, u_team_member', condition: 'For team_member: assigned_to == gs.getUserID()' },
      { table: 'u_project_task', operation: 'write', role: 'u_project_manager, u_team_member', condition: 'For team_member: assigned_to == gs.getUserID()' }
    ];
    
    cols = ['Context Table', 'Access Op', 'Role Constraint', 'Conditional evaluation (Row-level Script)'];
    
    const tr = document.createElement('tr');
    cols.forEach(c => tr.innerHTML += `<th>${c}</th>`);
    header.appendChild(tr);

    acls.forEach(acl => {
      const rTr = document.createElement('tr');
      rTr.innerHTML = `
        <td class="monospace" style="font-weight:600;">${acl.table}</td>
        <td><span class="badge-priority p2">${acl.operation}</span></td>
        <td><code class="monospace" style="color: var(--warning);">${acl.role}</code></td>
        <td style="font-family: var(--font-mono); font-size:11px; color: var(--text-muted);">${acl.condition}</td>
      `;
      tbody.appendChild(rTr);
    });
    
    document.getElementById('adminCount').innerText = `Showing 8 security ACL records`;
  }
}

// 4. Notifications (sys_email log) List Render
function renderNotifications() {
  const container = document.getElementById('notifList');
  if (!container) return;

  if (system.notifications.length === 0) {
    container.innerHTML = `<div class="notif-empty">No notifications sent. Try triggering a workflow!</div>`;
    return;
  }

  container.innerHTML = '';
  system.notifications.forEach(n => {
    const item = document.createElement('div');
    item.className = 'notif-item';
    item.innerHTML = `
      <div class="notif-meta">
        <span>To: ${n.recipient}</span>
        <span>Sent: ${n.sent}</span>
      </div>
      <div class="notif-subject">${escapeHtml(n.subject)}</div>
      <div class="notif-body">${escapeHtml(n.body)}</div>
    `;
    container.appendChild(item);
  });
}

// 5. XML update set previewer
function renderXmlPreview() {
  const viewer = document.getElementById('xmlViewer');
  if (!viewer) return;

  // Let's fetch the XML file from the configs directory locally, or display an authentic subset if fetch fails.
  // Since we are running in the browser, we try to load the local file.
  fetch('../servicenow_configs/update_set_rbac_workflow.xml')
    .then(response => {
      if (!response.ok) throw new Error("Could not find file");
      return response.text();
    })
    .then(xmlText => {
      viewer.textContent = xmlText;
    })
    .catch(err => {
      // Fallback display if not running in local server yet
      viewer.textContent = `<!-- Fallback Update Set View. Loading file failed: ${err.message} -->\n<!-- The physical Update Set was written to /servicenow_configs/update_set_rbac_workflow.xml -->`;
    });
}

// ============================================================================
// RECORD FORMS & MODAL CONTROLLERS (WITH ACL VALIDATION)
// ============================================================================

// A. Project Modal Actions
function openProjectModal(projectId = null) {
  const modal = document.getElementById('projectModal');
  const title = document.getElementById('projectModalTitle');
  const deleteBtn = document.getElementById('deleteProjectBtn');
  const saveBtn = document.getElementById('saveProjectBtn');

  // Fill PM managers dropdown
  const pmSelect = document.getElementById('projectManager');
  pmSelect.innerHTML = '';
  system.users.filter(u => u.roles.includes('u_project_manager')).forEach(pm => {
    pmSelect.innerHTML += `<option value="${pm.id}">${pm.firstName} ${pm.lastName}</option>`;
  });

  const form = document.getElementById('projectForm');
  form.reset();

  if (projectId) {
    const project = system.projects.find(p => p.id === projectId);
    if (!project) return;
    
    // Evaluate ACL
    const hasWrite = system.hasAccess('u_project', 'write', project);
    const hasDelete = system.hasAccess('u_project', 'delete', project);

    title.innerText = `Edit Project - ${project.number}`;
    document.getElementById('projectId').value = project.id;
    document.getElementById('projectNumber').value = project.number;
    document.getElementById('projectName').value = project.name;
    document.getElementById('projectManager').value = project.manager;
    document.getElementById('projectStatus').value = project.status;
    document.getElementById('projectDescription').value = project.description;

    // Toggle fields disabled
    document.getElementById('projectName').disabled = !hasWrite;
    document.getElementById('projectManager').disabled = !hasWrite;
    document.getElementById('projectStatus').disabled = !hasWrite;
    document.getElementById('projectDescription').disabled = !hasWrite;

    saveBtn.style.display = hasWrite ? 'block' : 'none';
    deleteBtn.className = hasDelete ? 'btn btn-danger' : 'd-none';

    document.getElementById('projectFormAclBanner').innerHTML = `
      <i class="fa-solid fa-circle-info"></i>
      <div>
        <strong>ACL Level Access:</strong> You have <strong>${hasWrite ? 'Write' : 'Read-Only'}</strong> access to this Project record.
      </div>
    `;
  } else {
    // Creating new Project record
    title.innerText = "New Project Record";
    document.getElementById('projectId').value = '';
    document.getElementById('projectNumber').value = 'PRJ001' + (system.projects.length + 10001).toString().slice(1);
    
    document.getElementById('projectName').disabled = false;
    document.getElementById('projectManager').disabled = false;
    document.getElementById('projectStatus').disabled = false;
    document.getElementById('projectDescription').disabled = false;

    saveBtn.style.display = 'block';
    deleteBtn.className = 'd-none';

    document.getElementById('projectFormAclBanner').innerHTML = `
      <i class="fa-solid fa-circle-info"></i>
      <div>
        <strong>ACL Level Access:</strong> Creating new Project [u_project] requires the <strong>u_project_manager</strong> role.
      </div>
    `;
  }

  modal.classList.add('active');
}

window.closeProjectModal = function() {
  document.getElementById('projectModal').classList.remove('active');
};

document.getElementById('projectForm').addEventListener('submit', (e) => {
  e.preventDefault();
  
  const id = document.getElementById('projectId').value;
  const num = document.getElementById('projectNumber').value;
  const name = document.getElementById('projectName').value;
  const manager = document.getElementById('projectManager').value;
  const status = document.getElementById('projectStatus').value;
  const desc = document.getElementById('projectDescription').value;

  if (id) {
    // Update existing Project
    const projIdx = system.projects.findIndex(p => p.id === id);
    if (projIdx === -1) return;

    if (!system.hasAccess('u_project', 'write', system.projects[projIdx])) {
      alert("ACL violation: Write permission denied.");
      return;
    }

    system.projects[projIdx] = { id, number: num, name, manager, status, description: desc };
    sysLog(`[Database] User updated u_project record ${num}`, 'info');
  } else {
    // Create new Project
    if (!system.hasAccess('u_project', 'create')) {
      alert("ACL violation: Create permission denied.");
      return;
    }

    const newProj = {
      id: 'proj_' + Date.now(),
      number: num,
      name,
      manager,
      status,
      description: desc
    };
    system.projects.push(newProj);
    sysLog(`[Database] User created u_project record ${num}`, 'info');
  }

  system.saveDatabase();
  closeProjectModal();
  render();
});

document.getElementById('deleteProjectBtn').addEventListener('click', () => {
  const id = document.getElementById('projectId').value;
  if (!id) return;
  
  const proj = system.projects.find(p => p.id === id);
  if (!system.hasAccess('u_project', 'delete', proj)) {
    alert("ACL violation: Delete permission denied.");
    return;
  }

  if (confirm(`Are you sure you want to delete project ${proj.number}?`)) {
    system.projects = system.projects.filter(p => p.id !== id);
    sysLog(`[Database] User deleted u_project record ${proj.number}`, 'warn');
    system.saveDatabase();
    closeProjectModal();
    render();
  }
});

window.editProject = function(id) {
  openProjectModal(id);
};

window.deleteProject = function(id) {
  const proj = system.projects.find(p => p.id === id);
  if (!system.hasAccess('u_project', 'delete', proj)) {
    alert("ACL Violation: Delete permission denied.");
    sysLog(`[ACL Enforced] Blocked delete operation on u_project: ${proj.number}`, 'error');
    return;
  }

  if (confirm(`Delete project ${proj.number}?`)) {
    system.projects = system.projects.filter(p => p.id !== id);
    sysLog(`[Database] User deleted u_project record ${proj.number}`, 'warn');
    system.saveDatabase();
    render();
  }
};


// B. Task Modal Actions
function openTaskModal(taskId = null) {
  const modal = document.getElementById('taskModal');
  const title = document.getElementById('taskModalTitle');
  const deleteBtn = document.getElementById('deleteTaskBtn');
  const saveBtn = document.getElementById('saveTaskBtn');

  // Fill Projects dropdown
  const projSelect = document.getElementById('taskProject');
  projSelect.innerHTML = '';
  system.projects.forEach(p => {
    projSelect.innerHTML += `<option value="${p.id}">${p.number} - ${p.name}</option>`;
  });

  // Fill Team Members dropdown (users in Project Team Members group)
  const assignSelect = document.getElementById('taskAssignedTo');
  assignSelect.innerHTML = '<option value="">-- Unassigned --</option>';
  system.users.filter(u => u.roles.includes('u_team_member') || u.roles.includes('u_project_manager')).forEach(u => {
    assignSelect.innerHTML += `<option value="${u.id}">${u.firstName} ${u.lastName}</option>`;
  });

  const form = document.getElementById('taskForm');
  form.reset();

  if (taskId) {
    const task = system.tasks.find(t => t.id === taskId);
    if (!task) return;

    // Evaluate ACL permissions
    const hasWrite = system.hasAccess('u_project_task', 'write', task);
    const hasDelete = system.hasAccess('u_project_task', 'delete', task);

    title.innerText = `Edit Task - ${task.number}`;
    document.getElementById('taskId').value = task.id;
    document.getElementById('taskNumber').value = task.number;
    document.getElementById('taskShortDesc').value = task.short_description;
    document.getElementById('taskProject').value = task.u_project;
    document.getElementById('taskAssignedTo').value = task.assigned_to;
    document.getElementById('taskState').value = task.state;
    document.getElementById('taskPriority').value = task.priority;
    document.getElementById('taskDueDate').value = task.u_due_date || '';
    document.getElementById('taskEscalated').checked = task.u_escalated;
    document.getElementById('taskDescription').value = task.description;

    // Enable/disable form inputs based on ACL write permission
    document.getElementById('taskShortDesc').disabled = !hasWrite;
    document.getElementById('taskProject').disabled = !hasWrite;
    document.getElementById('taskAssignedTo').disabled = !hasWrite;
    document.getElementById('taskState').disabled = !hasWrite;
    document.getElementById('taskPriority').disabled = !hasWrite;
    document.getElementById('taskDueDate').disabled = !hasWrite;
    document.getElementById('taskDescription').disabled = !hasWrite;

    saveBtn.style.display = hasWrite ? 'block' : 'none';
    deleteBtn.className = hasDelete ? 'btn btn-danger' : 'd-none';

    document.getElementById('taskFormAclBanner').innerHTML = `
      <i class="fa-solid fa-circle-info"></i>
      <div>
        <strong>ACL Level Access:</strong> You have <strong>${hasWrite ? 'Write' : 'Read-Only'}</strong> access to this Task record.
      </div>
    `;
  } else {
    // Creating new task
    title.innerText = "New Task Record";
    document.getElementById('taskId').value = '';
    document.getElementById('taskNumber').value = 'PRJTASK' + (system.tasks.length + 10001).toString().slice(1);
    document.getElementById('taskEscalated').checked = false;

    document.getElementById('taskShortDesc').disabled = false;
    document.getElementById('taskProject').disabled = false;
    document.getElementById('taskAssignedTo').disabled = false;
    document.getElementById('taskState').disabled = false;
    document.getElementById('taskPriority').disabled = false;
    document.getElementById('taskDueDate').disabled = false;
    document.getElementById('taskDescription').disabled = false;

    saveBtn.style.display = 'block';
    deleteBtn.className = 'd-none';

    document.getElementById('taskFormAclBanner').innerHTML = `
      <i class="fa-solid fa-circle-info"></i>
      <div>
        <strong>ACL Level Access:</strong> Creating new Task [u_project_task] requires the <strong>u_project_manager</strong> role.
      </div>
    `;
  }

  modal.classList.add('active');
}

window.closeTaskModal = function() {
  document.getElementById('taskModal').classList.remove('active');
};

document.getElementById('taskForm').addEventListener('submit', (e) => {
  e.preventDefault();

  const id = document.getElementById('taskId').value;
  const num = document.getElementById('taskNumber').value;
  const shortDesc = document.getElementById('taskShortDesc').value;
  const project = document.getElementById('taskProject').value;
  const assigned = document.getElementById('taskAssignedTo').value;
  const state = document.getElementById('taskState').value;
  const pri = document.getElementById('taskPriority').value;
  const due = document.getElementById('taskDueDate').value;
  const desc = document.getElementById('taskDescription').value;

  if (id) {
    // Update Task
    const taskIdx = system.tasks.findIndex(t => t.id === id);
    if (taskIdx === -1) return;

    if (!system.hasAccess('u_project_task', 'write', system.tasks[taskIdx])) {
      alert("ACL violation: Write permission denied.");
      return;
    }

    const wasAssigned = system.tasks[taskIdx].assigned_to;
    
    system.tasks[taskIdx] = { 
      id, 
      number: num, 
      short_description: shortDesc, 
      u_project: project, 
      assigned_to: assigned, 
      state, 
      priority: pri,
      u_due_date: due,
      u_escalated: system.tasks[taskIdx].u_escalated, // keep escalated flag state
      description: desc 
    };

    sysLog(`[Database] User updated u_project_task record ${num}`, 'info');

    // Trigger workflow manually if task was unassigned and now assigned
    if (!wasAssigned && assigned) {
      sysLog(`[Flow Trigger] Task reassigned. Launching assignment notification.`, 'trigger');
      const assignee = system.users.find(u => u.id === assigned);
      const parentProj = system.projects.find(p => p.id === project);
      if (assignee) {
        system.flowRuns++;
        const email = {
          id: 'email_re_' + Date.now(),
          sent: new Date().toLocaleTimeString(),
          recipient: assignee.email,
          subject: `Task Assigned: ${shortDesc} (${num})`,
          body: `Hello ${assignee.firstName},\n\nYou have been assigned to task ${num} under Project: "${parentProj ? parentProj.name : 'Unknown'}".\n\nPlease begin working on this item.`
        };
        system.notifications.unshift(email);
        sysLog(`[Action] Email Queue: Created notification record (sys_email) for ${assignee.email}`, 'success');
        triggerBellAlert();
        system.saveDatabase();
      }
    }
  } else {
    // Create Task (Requires PM)
    if (!system.hasAccess('u_project_task', 'create')) {
      alert("ACL violation: Create permission denied.");
      return;
    }

    const newTask = {
      id: 'task_' + Date.now(),
      number: num,
      short_description: shortDesc,
      u_project: project,
      assigned_to: assigned,
      state,
      priority: pri,
      u_due_date: due,
      u_escalated: false,
      description: desc
    };

    // Execute flow designer triggers on creation!
    const finalTask = system.simulateWorkflowTrigger(newTask);
    system.tasks.push(finalTask);
    sysLog(`[Database] User created u_project_task record ${num}`, 'info');
  }

  system.saveDatabase();
  closeTaskModal();
  render();
});

document.getElementById('deleteTaskBtn').addEventListener('click', () => {
  const id = document.getElementById('taskId').value;
  if (!id) return;

  const task = system.tasks.find(t => t.id === id);
  if (!system.hasAccess('u_project_task', 'delete', task)) {
    alert("ACL violation: Delete permission denied.");
    return;
  }

  if (confirm(`Are you sure you want to delete task ${task.number}?`)) {
    system.tasks = system.tasks.filter(t => t.id !== id);
    sysLog(`[Database] User deleted u_project_task record ${task.number}`, 'warn');
    system.saveDatabase();
    closeTaskModal();
    render();
  }
});

window.editTask = function(id) {
  openTaskModal(id);
};

window.deleteTask = function(id) {
  const task = system.tasks.find(t => t.id === id);
  if (!system.hasAccess('u_project_task', 'delete', task)) {
    alert("ACL Violation: Delete permission denied.");
    sysLog(`[ACL Enforced] Blocked delete operation on u_project_task: ${task.number}`, 'error');
    return;
  }

  if (confirm(`Delete task ${task.number}?`)) {
    system.tasks = system.tasks.filter(t => t.id !== id);
    sysLog(`[Database] User deleted u_project_task record ${task.number}`, 'warn');
    system.saveDatabase();
    render();
  }
};


// ============================================================================
// AUTOMATED TEST SUITE INTEGRATION & UI
// ============================================================================

document.getElementById('runTestsBtn').addEventListener('click', () => {
  const testPanel = document.getElementById('testRunnerPanel');
  testPanel.classList.add('active');
  
  sysLog("[Test Engine] Launching automated governance & security test run...", "trigger");
  
  // Disable button during test run animation
  const runBtn = document.getElementById('runTestsBtn');
  runBtn.disabled = true;
  runBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Running Tests...`;

  setTimeout(() => {
    // Run core assertions
    const testResults = runSecurityTests(system);
    
    // Display results in drawer
    const listContainer = document.getElementById('testCasesList');
    listContainer.innerHTML = '';
    
    let passedCount = 0;
    let failedCount = 0;

    testResults.forEach(test => {
      const isPass = test.status === 'passed';
      if (isPass) passedCount++; else failedCount++;
      
      const item = document.createElement('div');
      item.className = `test-case-item ${test.status}`;
      item.innerHTML = `
        <div class="test-status-icon ${test.status}">
          <i class="fa-solid ${isPass ? 'fa-circle-check' : 'fa-circle-xmark'}"></i>
        </div>
        <div class="test-details">
          <div class="test-name">${test.name}</div>
          <div class="test-desc">${test.description}</div>
          <div class="test-logs">${test.logs}</div>
        </div>
      `;
      listContainer.appendChild(item);
    });

    // Update metrics
    document.getElementById('totalTestCount').innerText = testResults.length;
    document.getElementById('passedTestCount').innerText = passedCount;
    document.getElementById('failedTestCount').innerText = failedCount;

    // Reset button
    runBtn.disabled = false;
    runBtn.innerHTML = `<i class="fa-solid fa-play"></i> Run Security Tests`;
    
    sysLog(`[Test Engine] Completed. Passed: ${passedCount}, Failed: ${failedCount}.`, failedCount > 0 ? 'error' : 'success');
  }, 800); // add short delay for satisfying UI response
});

document.getElementById('closeTestPanelBtn').addEventListener('click', () => {
  document.getElementById('testRunnerPanel').classList.remove('active');
});

// ============================================================================
// BOOTSTRAP INITIALIZATION
// ============================================================================

// HTML Entity escaper
function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Kickstart rendering
sysLog("[System Workspace] Initialized ServiceNow Polar Next Experience.", "success");
sysLog(`[Session Management] Current Active User: Admin. Role: admin (Full Access).`, "info");
toggleNavAvailability();
render();
updateWorkflowMetrics();
// Render initial logs in Console
sysLog("[Flow Engine] u_project_task_assignment_escalation_flow is compiled and listening for table hooks.", "info");
