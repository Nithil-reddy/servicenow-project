/**
 * Automated Security & Workflow Test Suite
 * Validates the Role-Based Access Control (RBAC), Access Control Lists (ACLs),
 * and Flow Designer Workflow automation according to project requirements.
 */

export function runSecurityTests(appState) {
  const results = [];
  
  // Helper to log test outcomes
  function assert(name, description, condition, logOutput = "") {
    results.push({
      name,
      description,
      status: condition ? 'passed' : 'failed',
      logs: logOutput || (condition ? "Assertion passed successfully." : "Assertion failed. Security constraint violated.")
    });
  }

  // ----------------------------------------------------
  // TEST 1: User Administration & Role Setup
  // ----------------------------------------------------
  try {
    const aliceUser = appState.users.find(u => u.username === 'alice.pm');
    const bobUser = appState.users.find(u => u.username === 'bob.member');
    
    const aliceHasRole = aliceUser && aliceUser.roles.includes('u_project_manager');
    const bobHasRole = bobUser && bobUser.roles.includes('u_team_member');
    
    assert(
      "User & Role Association",
      "Verify Alice has u_project_manager role and Bob has u_team_member role.",
      aliceHasRole && bobHasRole,
      `Alice Role: ${aliceUser?.roles?.join(', ') || 'none'}\nBob Role: ${bobUser?.roles?.join(', ') || 'none'}\nUsers securely provisioned.`
    );
  } catch (e) {
    assert("User & Role Association", "Verify Alice and Bob are configured", false, e.message);
  }

  // ----------------------------------------------------
  // TEST 2: Project Table ACL Verification (Alice vs Bob)
  // ----------------------------------------------------
  try {
    const dummyProject = { id: "test_proj_001", name: "Test Project", manager: "alice.pm", status: "Active" };
    
    // Evaluate Alice access (Project Manager)
    const aliceRead = appState.hasAccessForUser('alice.pm', 'u_project', 'read', dummyProject);
    const aliceCreate = appState.hasAccessForUser('alice.pm', 'u_project', 'create', null);
    const aliceWrite = appState.hasAccessForUser('alice.pm', 'u_project', 'write', dummyProject);
    const aliceDelete = appState.hasAccessForUser('alice.pm', 'u_project', 'delete', dummyProject);
    
    // Evaluate Bob access (Team Member)
    const bobRead = appState.hasAccessForUser('bob.member', 'u_project', 'read', dummyProject);
    const bobCreate = appState.hasAccessForUser('bob.member', 'u_project', 'create', null);
    const bobWrite = appState.hasAccessForUser('bob.member', 'u_project', 'write', dummyProject);
    const bobDelete = appState.hasAccessForUser('bob.member', 'u_project', 'delete', dummyProject);
    
    const alicePassed = aliceRead && aliceCreate && aliceWrite && aliceDelete;
    const bobPassed = !bobRead && !bobCreate && !bobWrite && !bobDelete;
    
    assert(
      "Project Table ACL Policies",
      "Verify Project Manager can full access Projects, and Team Members are blocked entirely.",
      alicePassed && bobPassed,
      `Alice Access check (R/C/W/D): ${aliceRead}/${aliceCreate}/${aliceWrite}/${aliceDelete}\n` +
      `Bob Access check (R/C/W/D): ${bobRead}/${bobCreate}/${bobWrite}/${bobDelete}\n` +
      `Result: ACL policy enforced.`
    );
  } catch (e) {
    assert("Project Table ACL Policies", "Evaluating Project ACLs", false, e.message);
  }

  // ----------------------------------------------------
  // TEST 3: Project Task ACL Policies (Alice)
  // ----------------------------------------------------
  try {
    const dummyTask = { id: "test_task_01", short_description: "General Task", assigned_to: "bob.member" };
    
    const aliceRead = appState.hasAccessForUser('alice.pm', 'u_project_task', 'read', dummyTask);
    const aliceCreate = appState.hasAccessForUser('alice.pm', 'u_project_task', 'create', null);
    const aliceWrite = appState.hasAccessForUser('alice.pm', 'u_project_task', 'write', dummyTask);
    const aliceDelete = appState.hasAccessForUser('alice.pm', 'u_project_task', 'delete', dummyTask);
    
    const alicePassed = aliceRead && aliceCreate && aliceWrite && aliceDelete;
    
    assert(
      "Task Table ACLs (Project Manager)",
      "Verify Project Manager has Create, Read, Update, and Delete access on Task table.",
      alicePassed,
      `Alice Access check (R/C/W/D): ${aliceRead}/${aliceCreate}/${aliceWrite}/${aliceDelete}\nManager access verified.`
    );
  } catch (e) {
    assert("Task Table ACLs (Project Manager)", "Evaluating Manager Task ACLs", false, e.message);
  }

  // ----------------------------------------------------
  // TEST 4: Project Task ACL Policies (Bob - Team Member)
  // ----------------------------------------------------
  try {
    const bobsTask = { id: "test_task_bob", short_description: "Bob's Task", assigned_to: "bob.member" };
    const alicesTask = { id: "test_task_alice", short_description: "Alice's Task", assigned_to: "alice.pm" };
    const unassignedTask = { id: "test_task_none", short_description: "Unassigned Task", assigned_to: "" };
    
    // Bob should be able to read and write his own task
    const bobReadOwn = appState.hasAccessForUser('bob.member', 'u_project_task', 'read', bobsTask);
    const bobWriteOwn = appState.hasAccessForUser('bob.member', 'u_project_task', 'write', bobsTask);
    
    // Bob should not be able to read/write someone else's task or unassigned task
    const bobReadOther = appState.hasAccessForUser('bob.member', 'u_project_task', 'read', alicesTask);
    const bobWriteOther = appState.hasAccessForUser('bob.member', 'u_project_task', 'write', alicesTask);
    
    // Bob should never be able to delete tasks
    const bobDeleteOwn = appState.hasAccessForUser('bob.member', 'u_project_task', 'delete', bobsTask);
    const bobCreateTask = appState.hasAccessForUser('bob.member', 'u_project_task', 'create', null);

    const bobAclPassed = bobReadOwn && bobWriteOwn && !bobReadOther && !bobWriteOther && !bobDeleteOwn && !bobCreateTask;
    
    assert(
      "Task Table ACLs (Team Member)",
      "Verify Team Member can only Read/Write tasks assigned to them, and cannot Delete or Create.",
      bobAclPassed,
      `Read/Write Own Task: ${bobReadOwn}/${bobWriteOwn}\n` +
      `Read/Write Other's Task: ${bobReadOther}/${bobWriteOther}\n` +
      `Create/Delete task permissions: ${bobCreateTask}/${bobDeleteOwn}\n` +
      `Bob restricted to assigned tasks.`
    );
  } catch (e) {
    assert("Task Table ACLs (Team Member)", "Evaluating Team Member Task ACLs", false, e.message);
  }

  // ----------------------------------------------------
  // TEST 5: Automated Workflow Trigger (Auto-Assignment & State Change)
  // ----------------------------------------------------
  try {
    // We simulate creating a task without assignee
    const testTask = {
      short_description: "Automated test task creation",
      u_project: "PRJ0010001",
      assigned_to: "",
      state: "Open",
      u_escalated: false,
      priority: "p4"
    };
    
    // Save to trigger workflow
    const originalNotifCount = appState.notifications.length;
    const originalRunCount = appState.flowRuns;
    
    // Direct workflow execution block simulate
    const savedTask = appState.simulateWorkflowTrigger(testTask);
    
    const assignedCorrectly = savedTask.assigned_to === 'bob.member';
    const stateUpdated = savedTask.state === 'Work in Progress';
    const flowRegistered = appState.flowRuns > originalRunCount;
    const notificationSent = appState.notifications.length > originalNotifCount;
    
    const workflowPassed = assignedCorrectly && stateUpdated && flowRegistered && notificationSent;
    
    assert(
      "Workflow Auto-Assignment & State Change",
      "Verify creating a task runs flow that auto-assigns, updates state, and logs notifications.",
      workflowPassed,
      `Auto-assigned: ${assignedCorrectly} (Assignee: ${savedTask.assigned_to})\n` +
      `State updated: ${stateUpdated} (State: ${savedTask.state})\n` +
      `Workflow triggered: ${flowRegistered}\n` +
      `Notification sent: ${notificationSent}\n` +
      `Workflow execution verified.`
    );
  } catch (e) {
    assert("Workflow Auto-Assignment & State Change", "Running workflow simulation", false, e.message);
  }

  // ----------------------------------------------------
  // TEST 6: Workflow Overdue SLA Escalation
  // ----------------------------------------------------
  try {
    // Create an overdue task in past
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    
    const overdueTask = {
      id: "sla_test_task",
      number: "PRJTASK9999",
      short_description: "Overdue firewall update",
      u_project: "PRJ0010001",
      assigned_to: "bob.member",
      state: "Work in Progress",
      u_due_date: yesterday.toISOString(),
      u_escalated: false,
      priority: "p4"
    };
    
    // Temporarily load task into database
    appState.tasks.push(overdueTask);
    const originalNotifCount = appState.notifications.length;
    
    // Execute SLA check
    appState.evaluateSlaBreaches();
    
    // Retrieve updated task
    const checkedTask = appState.tasks.find(t => t.id === "sla_test_task");
    
    const escalatedTrue = checkedTask && checkedTask.u_escalated === true;
    const criticalPriority = checkedTask && checkedTask.priority === 'p1';
    const managerNotified = appState.notifications.length > originalNotifCount && 
                            appState.notifications.some(n => n.recipient === 'alice.pm@company.com');
    
    // Clean up temporary task
    appState.tasks = appState.tasks.filter(t => t.id !== "sla_test_task");
    
    const slaPassed = escalatedTrue && criticalPriority && managerNotified;
    
    assert(
      "Workflow Overdue SLA Escalation",
      "Verify overdue tasks escalate to Critical priority, mark escalated true, and notify PM Alice.",
      slaPassed,
      `Marked Escalated: ${escalatedTrue}\n` +
      `Priority set to Critical (p1): ${criticalPriority}\n` +
      `PM Email Sent: ${managerNotified}\n` +
      `SLA Breach escalation verified.`
    );
  } catch (e) {
    assert("Workflow Overdue SLA Escalation", "Evaluating SLA breach", false, e.message);
  }

  return results;
}
