const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    picture: String,
    username: { type: String, required: true },
    password: { type: String, required: true },
    permissionLevel: { type: String, enum: ['admin', 'manager', 'reviewer', 'member'], default: 'member' },
    teams: [String],
});

const TeamSchema = new mongoose.Schema({
  teamName: String,
  teamId: { type: String, required: true, unique: true },
  teams: [String], // Array of sub-team IDs
  teamCode: String,
  allowedSendToTeams: [String],
  allowedReceiveFromTeams: [String],
  userPermissions: [Object],
  parentTeam: String,
  taskStorage: { type: [Object], default: [] },
});

const TaskSchema = new mongoose.Schema({
  taskId: { type: String, required: true, unique: true },
  title: { type: String, required: true },
  team: String,
  receivedFrom: String,
  description: String,
  status: { type: String, enum: ['Pending Approval', 'To Do', 'In Progress', 'Done'] },
  priority: { type: String, enum: ['High', 'Medium', 'Low', 'None'] },
  type: String,
  estimatedHours: Number,
  actualHours: Number,
  valueGenerated: Number,
  assignedTo: [String],
  createdBy: String,
  subtasks: [String],
  subtaskLevel: Number,
  parent: String,
  createdAt: { type: Date, default: Date.now },
  deadline: String,
  completedAt: String,
  progressCalculated: Number,
  auction: {
    deadline: String,
    isAuctioned: Boolean,
    bids: [Object], // Storing bids as a JSON string
  },
  comments: [Object], // Storing comments as a JSON string
  valuation: {
    completionRating: Number,
    feedback: String, // Storing bids as a JSON string
  },
  tags: [String],
});
exports.User = mongoose.model('User', UserSchema);
exports.Team = mongoose.model('Team', TeamSchema);
exports.Task = mongoose.model('Task', TaskSchema);
