// Copyright (c) 2025 Pau Vallbona Comas. All rights reserved.
// Unauthorized copying, modification, distribution is prohibited.

require("dotenv").config();
const fs = require('fs');
const path = require('path');

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require("jsonwebtoken");
const http = require('http')
const https = require('https')
const mongoose = require('mongoose');
const bcrypt = require("bcrypt");

const app = express();

// Mock user data
const password = encodeURIComponent('Nw?F~j=v>p#3r2XptUCr');
const users = JSON.parse(fs.readFileSync(path.join(__dirname, 'mockUserData.json')));
const teamdata = JSON.parse(fs.readFileSync(path.join(__dirname, 'mockTeamData.json')));
const mongoURI = `mongodb://fynixdb:${password}@fynix-server-db.cluster-c1i0m8sw414x.us-east-2.docdb.amazonaws.com:27017/?tls=true&tlsCAFile=global-bundle.pem&replicaSet=rs0&readPreference=secondaryPreferred&retryWrites=false`
const {User,Team,Task} = require('./mongodbModels.js'); // Import Task model


mongoose.connect(mongoURI, {
    dbName: 'fynixdb',
    useNewUrlParser: true,
    useUnifiedTopology: true,
    ssl: true,
    tlsCAFile: './global-bundle.pem'  // AWS-provided CA file for SSL
})
.then(() => console.log('Connected to Amazon DocumentDB'))
.catch(err => console.error('Connection error:', err));

// Redirect HTTP to HTTPS
const forceHttps = (req, res, next) => {
    if (!req.secure) {
        // Construct HTTPS URL
        const httpsUrl = `https://${req.headers.host}${req.url}`;
        return res.redirect(301, httpsUrl);
    }
    next();
};
const domain = 'fynix.pro';
const isProd = fs.existsSync(`/etc/letsencrypt/live/${domain}`);
function sanitize(string) {
  const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      "/": '&#x2F;',
  };
  const reg = /[&<>"'/]/ig;
  return string.replace(reg, (match)=>(map[match]));
}

// Middleware
if(isProd){
    app.use(forceHttps);
}
app.use(bodyParser.json());
app.use(cookieParser());

// Serve Vue site
app.use(express.static(path.join(__dirname, 'dist')));

// Middleware to verify if the user is logged in
const isAuthenticated = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Unauthorized: Please log in first' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if the token is stored in the user's session
    const user = await User.findOne({ userId: decoded.userId });
    if (!user) return res.status(401).json({ message: "Invalid or expired token" });

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}



// API Endpoint for login
app.post('/api/login', async (req, res) => {
    let username = null;
    let password = null;
    let token = null;
    if(req.body){
        username = req.body.username;
        password = req.body.password;
    }
    let user = null;
    if(req.cookies.token){
	  token = req.cookies.token;
      try{
        user = await User.findOne({ userId: jwt.verify(token, process.env.JWT_SECRET).userId});
      } catch (error){
        user = null;
        res.clearCookie("token");
        return res.status(401).json({ message: 'Expired Token', error });
      }
	  if(!user){
	      res.clearCookie("token");
          return res.status(401).json({ message: 'Expired Token', error });
      }
    } else {
      if (!username) {
            if(!password)
                return res.status(200).json({})
            return res.status(401).json({ message: 'Invalid credentials' });
      }
	  //TODO validate email
	  user = await User.findOne({ userId: username });
	  if(!user){
	    return res.status(400).json({message: "Invalid email"});
	  } else {
	    const isMatch = await bcrypt.compare(password,user.password);
	    if(!isMatch){
	      return res.status(400).json({message: "Incorrect password"});
	    } else {
	      token = jwt.sign({ userId: user.userId }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
	    }
	  } 
    }


    // Set session data
    res.cookie("token", token, {
	httpOnly: true,
	secure: true,
	sameSite: "Strict",
    });

    return res.status(200).json({
      message: 'Login successful',
      user: { "userId": user.userId, "username": user.username, "picture": user.picture, "teams": user.teams, "permissionLevel": user.permissionLevel }
    });
    try{
    } catch (error) {
	    res.status(500).json({message: "Server error", error});
    }
});

app.post("/api/sync", isAuthenticated, async (req, res) => {
  try {
    const timestamp = req.body.timestamp; // Expecting an array of userIds

    /*
    // Validate request body
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ message: "Invalid request: Expected a list of userIds" });
    }

    // Query the database for users, excluding passwords
    const users = await User.find({ userId: { $in: userIds } }).select("-password");

    return res.status(200).json(users);
    */
    return res.status(200).json({})
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

// API Endpoint for logout
app.get('/api/logout', isAuthenticated, async (req, res) => {
  try {
    // Clear the cookie
    res.clearCookie("token");
    res.status(200).json({ message: "Logged out successfully" });

  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/get-users", isAuthenticated, async (req, res) => {
  try {
    const userIds = req.body; // Expecting an array of userIds

    // Validate request body
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return res.status(400).json({ message: "Invalid request: Expected a list of userIds" });
    }

    // Query the database for users, excluding passwords
    const users = await User.find({ userId: { $in: userIds } }).select("-password");

    return res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.get("/api/get-team-data", isAuthenticated, async (req, res) => {
  try {
    // Get the user's teams
    const userTeams = req.user.teams; // List of team IDs

    if (!userTeams || userTeams.length === 0) {
      return res.status(200).json({ teams: [] }); // Return an empty array if user has no teams
    }

    // Fetch teams from the database
    const teams = await Team.find({ teamId: { $in: userTeams } });

    if (!teams || teams.length === 0) {
      return res.status(404).json({ message: "No teams found" });
    }

    // Fetch all tasks belonging to these teams
    let tasks = [];

    // Create a map for quick lookup
    const teamMap = {};
    teams.forEach((team) => {
      teamMap[team.teamId] = { ...team.toObject(), taskStorage: [] };
    });

    for (let team of teams){
      let userRole = team.userPermissions.find((userT)=>userT.userId == req.user.userId)
      if(!userRole)
        console.log("No permission found",team.userPermissions,req.user.userId);
      userRole = userRole.permissionLevel;
      let foundTasks = null;

      switch(userRole){
        case "member":
          foundTasks = await Task.find({ team: team.teamId, assignedTo: req.user.userId});
          if(foundTasks.length) tasks.push(...foundTasks);
          break;
        case "reviewer":
          foundTasks = await Task.find({ team: team.teamId, assignedTo: req.user.userId});
          if(foundTasks.length) tasks.push(...foundTasks);
          foundTasks = await Task.find({ team: team.teamId, assignedTo: {$ne: req.user.userId}, type: "Review"});
          if(foundTasks.length) tasks.push(...foundTasks);
          break;
        case "manager":
          foundTasks = await Task.find({ team: team.teamId});
          if(foundTasks.length) tasks.push(...foundTasks);
          foundTasks = await Task.find({ team: {$in : [...team.teams, ...team.allowedSendToTeams]}, receivedFrom: { $exists: true, $ne: null}});
          for(let subteam of [...team.teams, ...team.allowedSendToTeams]){
            if (!teamMap[subteam]) {
              let subteamObject = await Team.findOne({ teamId: subteam });
              teamMap[subteam] = { ...subteamObject.toObject(), taskStorage: [] };
            }
          }

          if(foundTasks.length) tasks.push(...foundTasks);
          break;
      }
    }


    // Assign tasks to the corresponding teams
    tasks.forEach((task) => {
      if (teamMap[task.team]) {
        teamMap[task.team].taskStorage.push(task.toObject());
      }
    });

    // Convert the team map back to a list
    //const teamData = Object.values(teamMap);

    // Return the team data with tasks attached
    res.status(200).json({"lastSyncTime": Date.now().toString(), "teams":teamMap});

  } catch (error) {
    console.error("Error fetching team data:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/edit-task", isAuthenticated, async (req, res) => {
  try {
    const taskData = req.body; // Get task object from request body

    if (!taskData.taskId || !taskData.team) {
      return res.status(400).json({ message: "Missing required taskId or team" });
    }

    // Check if the user is authorized to edit tasks in this team
    const userTeams = req.user.teams;
    if (!userTeams.includes(taskData.team)) {
      return res.status(403).json({ message: "Unauthorized to edit tasks in this team" });
    }

    // Search for the task by team and taskId
    let task = await Task.findOne({ taskId: taskData.taskId });

    if (task) {
      // Update the existing task
      await Task.updateOne({taskId: taskData.taskId }, { $set: taskData });
      return res.status(200).json({ message: "Task updated successfully", task: taskData });
    } else {
      // Create a new task if not found
      const team = await Team.findOne({ teamId: taskData.team });
      const userRole = team?.userPermissions.find((userT)=>userT.userId == req.user.userId).permissionLevel;
      if(userRole == "manager") {
        const newTask = new Task(taskData);
        if(newTask.assignedTo.includes(req.user.userId)){
          newTask.type = "Assigned";
          newTask.status = "To Do";
        }
        await newTask.save();
        return res.status(201).json({ message: "New task created", task: newTask });
      } else
        return res.status(403).json({ message: "Unauthorized to create tasks in this team" });
    }
  } catch (error) {
    console.error("Error editing task:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/add-subtask", isAuthenticated, async (req, res) => {
  try {
    const newTask = req.body; // Expecting a new task object

    // Validate request body
    if (!newTask || !newTask.taskId || !newTask.parent || !newTask.team) {
      return res.status(400).json({ message: "Missing required fields: taskId, parent, or team" });
    }

    // Check if the user is authorized to modify tasks in this team
    const userTeams = req.user.teams;
    if (!userTeams.includes(newTask.team)) {
      return res.status(403).json({ message: "Unauthorized to add subtasks in this team" });
    }

    if(newTask.assignedTo.includes(req.user.userId)){
      newTask.type = "Assigned";
      newTask.status = "To Do";
    }
    // Insert the new task into the database
    await Task.create(newTask);

    // Update the parent task by adding the new task's ID to its subtasks list
    const updatedParent = await Task.findOneAndUpdate(
      { taskId: newTask.parent }, // Match by taskId and team
      { $push: { subtasks: newTask.taskId } }, // Add the new subtask ID
      { new: true } // Return the updated document
    );

    if (!updatedParent) {
      return res.status(404).json({ message: "Parent task not found" });
    }

    return res.status(201).json({
      message: "Subtask added successfully",
      newTask: newTask,
      updatedParent: updatedParent
    });

  } catch (error) {
    console.error("Error adding subtask:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/add-team", isAuthenticated, async (req, res) => {
  try {
    const newTeam = req.body; // Expecting a new team object

    // Validate request body
    if (!newTeam.teamId || !newTeam.teamName) {
      return res.status(400).json({ message: "Missing required fields: teamId or name" });
    }

    // Check if user is authorized to create a team (must be a manager or admin in the parent team, if applicable)
    if (newTeam.parent) {
      const parentTeam = await Team.findOne({ teamId: newTeam.parent });

      if (!parentTeam) {
        return res.status(404).json({ message: "Parent team not found" });
      }

      const userRole = parentTeam?.userPermissions.find((userT)=>userT.userId == req.user.userId).permissionLevel;

      if (!userRole || (userRole !== "manager" && userRole !== "admin")) {
        return res.status(403).json({ message: "Unauthorized to create a sub-team in this parent team" });
      }
    }

    // Insert the new team into the database
    await Team.create(newTeam);
    let newNewTeam = await Team.findOne({ teamId: newTeam.teamId });

    let newNewUser = await User.findOneAndUpdate(
        { userId: req.user.userId }, // Match by parent teamId
        { $push: { teams: newTeam.teamId } }, // Add the new teamId to the teams list
        { new: true } // Return the updated document
    );

    // If the new team has a parent, update the parent team by adding the new team ID
    if (newTeam.parent) {
      const updatedParent = await Team.findOneAndUpdate(
        { teamId: newTeam.parent }, // Match by parent teamId
        { $push: { teams: newTeam.teamId } }, // Add the new teamId to the teams list
        { new: true } // Return the updated document
      );

      if (!updatedParent) {
        return res.status(404).json({ message: "Parent team not found for update" });
      }
    }

    return res.status(201).json({
      message: "Team added successfully",
      newTeam: newNewTeam,
      newUser: newNewUser,
    });

  } catch (error) {
    console.error("Error adding team:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/task-accept", isAuthenticated, async (req, res) => {
  try {
    const task = req.body;
    const user = req.user; // Authenticated user

    if (!task || !task.taskId) {
      return res.status(400).json({ message: "Missing required task data" });
    }

    // Find the task in the database
    const existingTask = await Task.findOne({ taskId: task.taskId});

    if (!existingTask) {
      return res.status(404).json({ message: "Task not found" });
    }

    // Check if the user is assigned to this task
    if (!existingTask.assignedTo.includes(user.userId)) {
      return res.status(403).json({ message: "Unauthorized: You are not assigned to this task" });
    }

    // Update the task status to "To Do"
    existingTask.status = "To Do";
    existingTask.type = "Assigned";
    await existingTask.save();

    return res.status(200).json({
      message: "Task accepted successfully",
      taskId: task.taskId,
      status: existingTask.status,
    });
  } catch (error) {
    console.error("Error accepting task:", error);
    res.status(500).json({ message: "Server error", error });
  }
});


app.post("/api/task-assign", isAuthenticated, async (req, res) => {
  try {
    const taskId = req.body.taskId;
    const team = req.body.team;
    const assignedTo = req.body.assignedTo;
    const user = req.user; // Set by isAuthenticated middleware

    if (!taskId || !team || !assignedTo) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Find the task
    const task = await Task.findOne({ taskId });

    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    // Check if the user has manager permissions in the team
    const teamData = await Team.findOne({ teamId: team });
    const userRole = teamData?.userPermissions.find((userT)=>userT.userId == user.userId).permissionLevel;

    if (!teamData || !userRole || userRole !== "manager") {
      return res.status(403).json({ message: "Unauthorized: Only managers can assign tasks" });
    }

    // Update the task assignment
    task.assignedTo = assignedTo;
    task.type = "Assigned";
    task.status = "Pending Approval";

    await task.save();

    res.status(200).json({ message: "Task assigned successfully", updatedTask: task });
  } catch (error) {
    console.error("Error assigning task:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/task-forfeit", isAuthenticated, async (req, res) => {
  try {
    const taskId = req.body.taskId;
    const team = req.body.team;
    const user = req.user; // Set by isAuthenticated middleware

    if (!taskId || !team) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Find the task
    const task = await Task.findOne({ taskId });

    if (!task || !task.assignedTo.includes(req.user.userId)) {
      return res.status(404).json({ message: "Task not found in assigned tasks" });
    }

    // Ensure the task is in one of the user's teams
    if (!user.teams.includes(task.team)) {
      return res.status(403).json({ message: "Unauthorized: Task not in user teams" });
    }

    //Exception to remove task if created by the same user
    if(task.createdBy == user.userId && task.assignedTo.includes(user.userId)){
        await Task.findOneAndDelete({_id: task._id});
        return res.status(200).json({ message: "Task forfeited and deleted" });
    }

    if(task.type == "Unassigned"){
      if(!task.receivedFrom){
        await Task.findOneAndDelete({_id: task._id});
        return res.status(200).json({ message: "Task forfeited and deleted" });
      } else {
        task.team = task.receivedFrom;
        task.receivedFrom = null;
        await task.save();
        return res.status(200).json({ message: "Task forfeited successfully", updatedTask: task });
      }
    } else {
      task.type = "Unassigned";
      await task.save();
      return res.status(200).json({ message: "Task forfeited successfully", updatedTask: task });
    }

  } catch (error) {
    console.error("Error forfeiting task:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/place-bid", isAuthenticated, async (req, res) => {
  try {
    const taskId = req.body.task.taskId;
    const team = req.body.task.team;
    const bid = req.body.bid;
    const user = req.user; // Set by isAuthenticated middleware

    if (!taskId || !team || !bid || !bid.userId || !bid.bidHours) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Find the task
    const task = await Task.findOne({ taskId, team });

    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    // Ensure the task is in one of the user's teams
    if (!user.teams.includes(task.team)) {
      return res.status(403).json({ message: "Unauthorized: Task not in user teams" });
    }

    // Append the new bid
    task.auction.bids.push(bid);
    await task.save();

    return res.status(200).json({ message: "Bid placed successfully", updatedTask: task });
  } catch (error) {
    console.error("Error placing bid:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/task-transfer", isAuthenticated, async (req, res) => {
  try {
    const task = req.body.task;
    const team = task.team;
    const newTeam = req.body.teamId;
    const user = req.user; // Set by isAuthenticated middleware

    if (!task || !task.taskId || !team || !newTeam) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Find the task
    const foundTask = await Task.findOne({taskId: task.taskId });

    if (!foundTask) {
      return res.status(404).json({ message: "Task not found" });
    }

    // Check if the user has manager permissions in the team
    const teamData = await Team.findOne({ teamId: team });
    const userRole = teamData?.userPermissions.find((userT)=>userT.userId == user.userId).permissionLevel;

    if (!teamData || !userRole || userRole !== "manager") {
      return res.status(403).json({ message: "Unauthorized: Only managers can transfer tasks" });
    }

    // Transfer the task
    foundTask.type = "Unassigned";
    if(!foundTask.receivedFrom)
      foundTask.receivedFrom = task.team;
    foundTask.team = newTeam;
    await foundTask.save();

    return res.status(200).json({ message: "Task transferred successfully", updatedTask: foundTask });
  } catch (error) {
    console.error("Error transferring task:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/task-review", isAuthenticated, async (req, res) => {
  try {
    const taskId = req.body.taskId;
    const team = req.body.team;
    const valuation = req.body.valuation;
    const user = req.user; // Set by isAuthenticated middleware

    if (!taskId || !team || !valuation) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Find the task
    const task = await Task.findOne({ taskId });

    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    // Check if the user has manager or reviewer permissions in the team
    const teamData = await Team.findOne({ teamId: team });
    const userRole = teamData?.userPermissions.find((userT)=>userT.userId == user.userId).permissionLevel;

    if (!teamData || !userRole || (userRole !== "manager" && userRole !== "reviewer")) {
      return res.status(403).json({ message: "Unauthorized: Only managers or reviewers can review tasks" });
    }

    // Update the task valuation
    task.valuation = valuation;
    task.status = "Done";
    task.type = "Assigned";

    await task.save();

    res.status(200).json({ message: "Task reviewed successfully", updatedTask: task });
  } catch (error) {
    console.error("Error reviewing task:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/task-auction", isAuthenticated, async (req, res) => {
  try {
    const taskId = req.body.taskId;
    const team = req.body.team;
    const auction = req.body.auction;
    const user = req.user; // Set by isAuthenticated middleware

    if (!taskId || !team || !auction || !auction.deadline) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Find the task
    const task = await Task.findOne({ taskId });

    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    // Check if the user has manager or reviewer permissions in the team
    const teamData = await Team.findOne({ teamId: team });
    const userRole = teamData?.userPermissions.find((userT)=>userT.userId == user.userId).permissionLevel;

    if (!teamData || !userRole || (userRole !== "manager")) {
      return res.status(403).json({ message: "Unauthorized: Only managers can update auctions" });
    }

    // Update the task auction details
    task.auction.deadline = auction.deadline;
    task.auction.isAuctioned = false;
    task.auction.bids = [];
    task.status = "Pending Approval";
    task.type = "Auctioned";

    await task.save();

    res.status(200).json({ message: "Task auction updated successfully", updatedTask: task });
  } catch (error) {
    console.error("Error updating task auction:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/task-auction-update", isAuthenticated, async (req, res) => {
  try {
    const { taskId, team } = req.body;

    // Validate request body
    if (!taskId || !team) {
      return res.status(400).json({ message: "Missing required fields: taskId or team" });
    }

    // Find the latest version of the task
    const task = await Task.findOne({ taskId });

    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    // Check if the task is an auctioned task
    if (!task.auction || !task.auction.deadline) {
      return res.status(400).json({ message: "Task is not an auctioned task or missing deadline" });
    }

    const auctionDeadline = new Date(task.auction.deadline);
    const now = new Date();

    // If auction deadline has not passed, do nothing
    if (now < auctionDeadline) {
      return res.status(200).json({ message: "Auction is still ongoing", task });
    }

    // Auction has ended, process bids
    if (task.auction.bids && task.auction.bids.length > 0) {
      // Select the bid with the lowest bidHours
      const winningBid = task.auction.bids.reduce((prev, current) =>
        prev.bidHours < current.bidHours ? prev : current
      );

      // Assign the task to the winning bidder
      task.type = "Assigned";
      task.assignedTo = [winningBid.userId];
      task.status = "To Do";
      task.auction.isAuctioned = true;
    } else {
      // No bids, mark task as unassigned
      task.type = "Unassigned";
      task.status = "Pending Approval";
    }

    // Save the updated task
    await task.save();

    return res.status(200).json({
      message: "Auction update processed successfully",
      updatedTask: task
    });

  } catch (error) {
    console.error("Error updating auctioned task:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/update-team", isAuthenticated, async (req, res) => {
  try {
    const team = req.body;
    const user = req.user; // Set by isAuthenticated middleware

    if (!team || !team.teamId) {
      return res.status(400).json({ message: "Missing required team data" });
    }

    // Find the team
    let existingTeam = await Team.findOne({ teamId: team.teamId });

    if (!existingTeam) {
      return res.status(404).json({ message: "Team not found" });
    }

    const userRole = existingTeam?.userPermissions.find((userT)=>userT.userId == user.userId).permissionLevel;
    // Check if the user has permission
    if (userRole != "manager") {
      return res.status(403).json({ message: "Unauthorized: No permission to edit this team" });
    }

    existingTeam.teamName = team.teamName;
    await existingTeam.save();
    for (let permission of existingTeam.userPermissions){
      let foundPermission = team.userPermissions.find(permissionT => permissionT.userId == permission.userId);
      if(foundPermission){
        await Team.updateOne(
          {
            "teamId": team.teamId,
            "userPermissions.userId": permission.userId
          },
          {
            $set: {
              "userPermissions.$.permissionLevel": foundPermission.permissionLevel
            }
          }
        );
      } else
        return res.status(404).json({ message: `User not found: ${permission.userId}` });
    }
    // Update the team in the database
    //await Team.updateOne({ teamId: team.teamId }, { $set: team });

    return res.status(200).json({ message: "Team updated successfully", updatedTeam: existingTeam });
  } catch (error) {
    console.error("Error updating team:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/add-send-to-team", isAuthenticated, async (req, res) => {
  try {
    const teamId = req.body.teamId;
    const sendToTeamCode = req.body.sendToTeam;
    const user = req.user; // Set by isAuthenticated middleware

    if (!teamId || !sendToTeamCode) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Find the current team
    const currentTeam = await Team.findOne({ teamId: teamId });

    if (!currentTeam) {
      return res.status(404).json({ message: "Current team not found" });
    }

    const userRole = currentTeam?.userPermissions.find((userT)=>userT.userId == user.userId).permissionLevel;
    // Check if user has permission
    if (userRole != "manager") {
      return res.status(403).json({ message: "Unauthorized: No permission to edit this team" });
    }

    // Find the team to send to
    const targetTeam = await Team.findOne({ teamCode: sendToTeamCode });

    if (!targetTeam) {
      return res.status(404).json({ message: "Target team not found" });
    }

    // Add the found team to the allowedSendToTeams list
    await Team.updateOne(
      { teamId: teamId },
      { $addToSet: { allowedSendToTeams: targetTeam.teamId } }
    );
    await Team.updateOne(
      { teamId: targetTeam.teamId },
      { $addToSet: { allowedReceiveFromTeams: teamId } }
    );

    return res.status(200).json({ message: "Send-to team added successfully", targetTeamId: targetTeam.teamId });
  } catch (error) {
    console.error("Error adding send-to team:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/add-user", isAuthenticated, async (req, res) => {
  try {
    const teamId = req.body.teamId;
    const newUserId = req.body.userId;
    const user = req.user; // Authenticated user

    if (!teamId || !newUserId) {
      return res.status(400).json({ message: "Missing required team or user data" });
    }

    // Find the team in the database
    let existingTeam = await Team.findOne({ teamId: teamId});

    if (!existingTeam) {
      return res.status(404).json({ message: "Team not found" });
    }

    // Check if the user has permission to edit the team
    const userRole = existingTeam?.userPermissions.find((userT)=>userT.userId == user.userId).permissionLevel;
    if (userRole != "manager") {
      return res.status(403).json({ message: "Unauthorized: No permission to edit this team" });
    }

    // Check if the user exists in the database
    let existingUser = await User.findOne({ userId: newUserId});

    if (!existingUser) {
      // Create a new user with default values
      const username = newUserId.split("@")[0]; // Extract username before '@'

      existingUser = new User({
        userId: newUserId,
        username: username,
        teams: [],
        picture: null,
        permissionLevel: "member",
        password: bcrypt.hashSync("1234",9), // Default password (should be changed later)
      });

      await existingUser.save();
    }
    
    await User.findOneAndUpdate(
        { userId: newUserId }, // Match by taskId and team
        { $push: { teams: teamId } }, // Add the new subtask ID
      );

    // Add the new user to the team's userPermissions if not already added
    if (!existingTeam.userPermissions.some((userT) => userT.userId == newUserId)) {
      let newPermission = {"userId": newUserId ,"permissionLevel": "member"};
      existingTeam = await Team.findOneAndUpdate(
        { teamId: teamId }, // Match by taskId and team
        { $push: { userPermissions: newPermission } }, // Add the new subtask ID
      );
    }

    return res.status(200).json({
      message: "User added successfully",
      teamId: teamId,
      userId: newUserId,
    });
  } catch (error) {
    console.error("Error adding user to team:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/api/change-password", isAuthenticated, async (req, res) => {
  try {
    const password = req.body.password;
    const userId = req.user.userId; // Get authenticated user ID

    if (!password || password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters long" });
    }

    // Hash the new password
    const hashedPassword = bcrypt.hashSync(password, 9);

    // Update the password in the database
    const updatedUser = await User.findOneAndUpdate(
      { userId: userId },
      { password: hashedPassword },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error("Error updating password:", error);
    res.status(500).json({ message: "Server error", error });
  }
});


// Fallback route for Vue app
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});
app.get('/main', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});
app.get('/inbox', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});
app.get('/auction', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});
app.get('/settings', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

if(isProd) {
    const options = {
        key: fs.readFileSync(`/etc/letsencrypt/live/${domain}/privkey.pem`),
        cert: fs.readFileSync(`/etc/letsencrypt/live/${domain}/cert.pem`),
        ca: fs.readFileSync(`/etc/letsencrypt/live/${domain}/chain.pem`),
    };
    http.createServer(app).listen(80, () => {
        console.log('HTTP server listening on port 80 and redirecting to HTTPS');
    });
    https.createServer(options,app).listen(443,() => {
        console.log('HTTPS server running on port 443');
    });
} else {
    // Start server
    app.listen(80, () => {
    console.log(`Server running on http://localhost:80`);
});
}
