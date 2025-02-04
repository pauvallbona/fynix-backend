const mongoose = require("mongoose");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");

// Database Connection URI
const password = encodeURIComponent('Nw?F~j=v>p#3r2XptUCr');
const MONGO_URI = `mongodb://fynixdb:${password}@fynix-server-db.cluster-c1i0m8sw414x.us-east-2.docdb.amazonaws.com:27017/?tls=true&tlsCAFile=global-bundle.pem&replicaSet=rs0&readPreference=secondaryPreferred&retryWrites=false`;

//Define Schemas
const {User,Team,Task} = require('./mongodbModels.js'); // Import Task model


// Read Mock Files
const mockUserDataPath = path.join(__dirname, "mockUserData.json");
const mockTeamDataPath = path.join(__dirname, "mockTeamData.json");

const mockUserData = JSON.parse(fs.readFileSync(mockUserDataPath, "utf8"));
const mockTeamData = JSON.parse(fs.readFileSync(mockTeamDataPath, "utf8"));

// Connect to MongoDB
async function connectDB() {
  try {
    await mongoose.connect(MONGO_URI, {
      dbName: 'fynixdb',
      useNewUrlParser: true,
      useUnifiedTopology: true,
      ssl: true,
      tlsCAFile: './global-bundle.pem'  // AWS-provided CA file for SSL
    });
    console.log("✅ Connected to MongoDB successfully");
  } catch (error) {
    console.error("❌ MongoDB Connection Error:", error);
    process.exit(1);
  }
}

// Insert Users
async function insertUsers() {
  try {
    await User.deleteMany(); // Clear existing data
    for (let user of mockUserData){
      user.password = bcrypt.hashSync(user.password,9);
    }
    await User.insertMany(mockUserData);
    console.log("✅ Users inserted successfully");
  } catch (error) {
    console.error("❌ Error inserting users:", error);
  }
}

// Insert Teams and Extract Tasks
async function insertTeamsAndTasks() {
  try {
    await Team.deleteMany(); // Clear existing teams
    await Task.deleteMany(); // Clear existing tasks

    let teamsToInsert = [];
    let tasksToInsert = [];

    for (let team of mockTeamData) {
      // Extract tasks from team object
      let teamT = {};
      teamT.teamName = team.teamName;
      teamT.teamCode =  team.teamCode;
      teamT.teamId = team.teamId;
      teamT.teams = team.teams;
      teamT.allowedSendToTeams = team.allowedSendToTeams;
      teamT.allowedReceiveFromTeams = team.allowedReceiveFromTeams;
      teamT.userPermissions = team.userPermissions;
      teamsToInsert.push({...teamT});

      if (team.taskStorage && team.taskStorage.length > 0) {
        for (let task of team.taskStorage) {
          tasksToInsert.push({
            ...task,
            team: team.teamId, // Store the team ID as parent
            /*
            auction: {
              isAuctioned: task.auction?.isAuctioned || false,
              bids: JSON.stringify(task.auction?.bids || []), // Stringify bids
            },
            comments: JSON.stringify(task.comments || []), // Stringify comments
            */
          });
        }
      }
    }

    // Insert teams into DB
    await Team.insertMany(teamsToInsert);
    console.log("✅ Teams inserted successfully");

    // Insert tasks into DB
    if (tasksToInsert.length > 0) {
      await Task.insertMany(tasksToInsert);
      console.log(`✅ ${tasksToInsert.length} Tasks inserted successfully`);
    } else {
      console.log("⚠️ No tasks found in mockTeamData");
    }
  } catch (error) {
    console.error("❌ Error inserting teams or tasks:", error);
  }
}

// Run Import Script
async function importData() {
  await connectDB();
  await insertUsers();
  await insertTeamsAndTasks();
  console.log("✅ Import completed");
  mongoose.connection.close();
}

importData();

