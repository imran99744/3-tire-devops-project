const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { testConnection } = require('./config/database');
const { pool } = require('./config/database');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ message: 'Server is running', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Create default admin user
async function createDefaultAdmin() {
  try {
    const [existingAdmin] = await pool.execute(
      'SELECT id FROM users WHERE email = ?',
      ['admin@admin.com']
    );

    if (existingAdmin.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 12);
      await pool.execute(
        'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
        ['Admin User', 'admin@admin.com', hashedPassword, 'admin']
      );
      console.log('✅ Default admin user created:');
      console.log('   Email: admin@admin.com');
      console.log('   Password: admin123');
    }
  } catch (error) {
    console.error('Error creating default admin:', error.message);
  }
}

// Start server
async function startServer() {
  // Test database connection
  const dbConnected = await testConnection();
  
  if (!dbConnected) {
    console.error('Failed to connect to database. Please check your MySQL configuration.');
    process.exit(1);
  }

  // Create default admin user
  await createDefaultAdmin();

  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📊 API endpoints available at http://localhost:${PORT}/api`);
  });
}

startServer().catch(console.error);