const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Enhanced CORS configuration
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Handle preflight requests
app.options('*', cors());

app.use(express.json());
app.use(express.static(__dirname));

// Database initialization
const db = new sqlite3.Database('./library.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        initializeDatabase();
    }
});

// Initialize database tables
function initializeDatabase() {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student',
        joined_date TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // Books table
    db.run(`CREATE TABLE IF NOT EXISTS books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        isbn TEXT UNIQUE NOT NULL,
        genre TEXT NOT NULL,
        publication_year INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        available INTEGER NOT NULL,
        description TEXT,
        added_date TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // Borrowings table
    db.run(`CREATE TABLE IF NOT EXISTS borrowings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        book_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        borrowed_date TEXT NOT NULL,
        due_date TEXT NOT NULL,
        returned_date TEXT,
        FOREIGN KEY (book_id) REFERENCES books (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Insert default books
    const defaultBooks = [
        {
            title: "The Great Gatsby",
            author: "F. Scott Fitzgerald",
            isbn: "9780743273565",
            genre: "Fiction",
            publication_year: 1925,
            quantity: 10,
            available: 8,
            description: "A classic novel of the Jazz Age."
        },
        {
            title: "To Kill a Mockingbird",
            author: "Harper Lee",
            isbn: "9780061120084",
            genre: "Fiction",
            publication_year: 1960,
            quantity: 8,
            available: 5,
            description: "A tale of race and identity."
        },
        {
            title: "1984",
            author: "George Orwell",
            isbn: "9780451524935",
            genre: "Fiction",
            publication_year: 1949,
            quantity: 12,
            available: 12,
            description: "A dystopian social science fiction novel."
        },
        {
            title: "Pride and Prejudice",
            author: "Jane Austen",
            isbn: "9780141439518",
            genre: "Fiction",
            publication_year: 1813,
            quantity: 7,
            available: 3,
            description: "A romantic novel of manners."
        },
        {
            title: "The Hobbit",
            author: "J.R.R. Tolkien",
            isbn: "9780547928227",
            genre: "Fantasy",
            publication_year: 1937,
            quantity: 9,
            available: 6,
            description: "A fantasy novel about Bilbo Baggins."
        }
    ];

    // Create demo users
    createDemoUsers();
    
    // Insert default books
    defaultBooks.forEach(book => {
        db.get('SELECT id FROM books WHERE isbn = ?', [book.isbn], (err, row) => {
            if (err) return;
            if (!row) {
                db.run(
                    `INSERT INTO books (title, author, isbn, genre, publication_year, quantity, available, description) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [book.title, book.author, book.isbn, book.genre, book.publication_year, book.quantity, book.available, book.description]
                );
            }
        });
    });
}

// Separate function to create demo users
function createDemoUsers() {
    const demoUsers = [
        {
            name: "Demo Student",
            email: "student@example.com",
            password: "password123",
            role: "student"
        },
        {
            name: "Demo Librarian", 
            email: "librarian@example.com",
            password: "password123",
            role: "librarian"
        }
    ];

    demoUsers.forEach(user => {
        // Check if user already exists
        db.get('SELECT id FROM users WHERE email = ?', [user.email], (err, row) => {
            if (err) return;
            
            if (!row) {
                // Create new user
                const hashedPassword = bcrypt.hashSync(user.password, 10);
                db.run(
                    'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
                    [user.name, user.email, hashedPassword, user.role]
                );
            }
        });
    });
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader) {
        return res.status(401).json({ error: 'Access token required' });
    }

    const userId = authHeader.replace(/['"]/g, '');
    
    if (!userId || isNaN(parseInt(userId))) {
        return res.status(403).json({ error: 'Invalid token format' });
    }

    db.get('SELECT * FROM users WHERE id = ?', [parseInt(userId)], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(403).json({ error: 'Invalid token' });
        }

        req.user = user;
        next();
    });
};

// API Routes

// User registration
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        
        if (!name || !email || !password || !role) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (row) return res.status(400).json({ error: 'User already exists' });

            const hashedPassword = await bcrypt.hash(password, 10);
            db.run(
                'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
                [name, email, hashedPassword, role],
                function(err) {
                    if (err) return res.status(500).json({ error: 'Error creating user' });
                    
                    // ✅ ADDED: Log user registration
                    console.log(`📝 NEW USER REGISTERED: ${name} (${email}) as ${role} | ID: ${this.lastID} | Time: ${new Date().toLocaleString()}`);
                    
                    res.status(201).json({
                        id: this.lastID,
                        name,
                        email,
                        role,
                        joined: new Date().toLocaleString('default', { month: 'long', year: 'numeric' })
                    });
                }
            );
        });
    } catch (error) {
        console.error('❌ REGISTRATION ERROR:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// User login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            console.log(`⚠️  FAILED LOGIN ATTEMPT: ${email} - User not found`);
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const validPassword = bcrypt.compareSync(password, user.password);
        
        if (!validPassword) {
            console.log(`⚠️  FAILED LOGIN ATTEMPT: ${email} - Invalid password`);
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // ✅ ADDED: Log successful login
        console.log(`🔐 USER LOGIN: ${user.name} (${user.email}) as ${user.role} | ID: ${user.id} | Time: ${new Date().toLocaleString()}`);

        res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            joined: new Date(user.joined_date).toLocaleString('default', { month: 'long', year: 'numeric' })
        });
    });
});

// Get all books
app.get('/api/books', (req, res) => {
    const { search } = req.query;
    let query = `
        SELECT b.*, 
            (b.quantity - IFNULL((
                SELECT COUNT(*) 
                FROM borrowings br 
                WHERE br.book_id = b.id AND br.returned_date IS NULL
            ), 0)) as available
        FROM books b
    `;
    let params = [];

    if (search) {
        query += ` WHERE b.title LIKE ? OR b.author LIKE ? OR b.isbn LIKE ?`;
        params = [`%${search}%`, `%${search}%`, `%${search}%`];
    }

    query += ` ORDER BY b.title`;

    db.all(query, params, (err, books) => {
        if (err) {
            console.error('Error fetching books:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(books);
    });
});

// Add new book (librarian only)
app.post('/api/books', authenticateToken, (req, res) => {
    if (req.user.role !== 'librarian') {
        console.log(`🚫 UNAUTHORIZED BOOK ADD ATTEMPT: ${req.user.name} (${req.user.email}) tried to add book`);
        return res.status(403).json({ error: 'Only librarians can add books' });
    }

    const { title, author, isbn, genre, publication_year, quantity, description } = req.body;

    if (!title || !author || !isbn || !genre || !publication_year || !quantity) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    db.get('SELECT id FROM books WHERE isbn = ?', [isbn], (err, existingBook) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (existingBook) {
            console.log(`📚 DUPLICATE BOOK ATTEMPT: ISBN ${isbn} already exists`);
            return res.status(400).json({ error: 'A book with this ISBN already exists' });
        }

        db.run(
            `INSERT INTO books (title, author, isbn, genre, publication_year, quantity, available, description) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [title, author, isbn, genre, publication_year, quantity, quantity, description || ''],
            function(err) {
                if (err) {
                    console.error('Error inserting book:', err);
                    return res.status(500).json({ error: 'Failed to add book to database' });
                }

                // ✅ ADDED: Log book addition
                console.log(`📖 NEW BOOK ADDED: "${title}" by ${author} | ISBN: ${isbn} | Genre: ${genre} | Quantity: ${quantity} | Added by: ${req.user.name} | Time: ${new Date().toLocaleString()}`);

                const newBook = {
                    id: this.lastID,
                    title,
                    author,
                    isbn,
                    genre,
                    publication_year,
                    quantity,
                    available: quantity,
                    description: description || ''
                };

                res.status(201).json(newBook);
            }
        );
    });
});

// Update book (librarian only)
app.put('/api/books/:bookId', authenticateToken, (req, res) => {
    if (req.user.role !== 'librarian') {
        console.log(`🚫 UNAUTHORIZED BOOK UPDATE ATTEMPT: ${req.user.name} (${req.user.email}) tried to update book ID ${req.params.bookId}`);
        return res.status(403).json({ error: 'Only librarians can edit books' });
    }

    const { bookId } = req.params;
    const { title, author, genre, publication_year, quantity, description } = req.body;

    if (!title || !author || !genre || !publication_year || !quantity) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Calculate new available count based on current borrowings
    db.get(
        `SELECT 
            quantity as old_quantity,
            (quantity - IFNULL((
                SELECT COUNT(*) 
                FROM borrowings br 
                WHERE br.book_id = books.id AND br.returned_date IS NULL
            ), 0)) as current_available
        FROM books WHERE id = ?`,
        [bookId],
        (err, book) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (!book) {
                return res.status(404).json({ error: 'Book not found' });
            }

            // Calculate new available count
            const borrowedCount = book.old_quantity - book.current_available;
            const newAvailable = Math.max(0, quantity - borrowedCount);

            db.run(
                `UPDATE books SET title = ?, author = ?, genre = ?, publication_year = ?, 
                 quantity = ?, available = ?, description = ? WHERE id = ?`,
                [title, author, genre, publication_year, quantity, newAvailable, description, bookId],
                function(err) {
                    if (err) {
                        console.error('Error updating book:', err);
                        return res.status(500).json({ error: 'Error updating book' });
                    }
                    if (this.changes === 0) return res.status(404).json({ error: 'Book not found' });
                    
                    // ✅ ADDED: Log book update
                    console.log(`✏️  BOOK UPDATED: ID ${bookId} - "${title}" by ${author} | Updated by: ${req.user.name} | Time: ${new Date().toLocaleString()}`);
                    
                    res.json({ message: 'Book updated successfully' });
                }
            );
        }
    );
});

// Get user's borrowed books
app.get('/api/users/:userId/borrowings', authenticateToken, (req, res) => {
    const { userId } = req.params;
    
    if (req.user.id != userId && req.user.role !== 'librarian') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const query = `
        SELECT b.id as book_id, b.title as book_title, b.author, 
            br.borrowed_date, br.due_date, br.returned_date, br.id as id
        FROM borrowings br
        JOIN books b ON br.book_id = b.id
        WHERE br.user_id = ?
        ORDER BY br.borrowed_date DESC
    `;

    db.all(query, [userId], (err, borrowings) => {
        if (err) {
            console.error('Error fetching borrowings:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(borrowings);
    });
});

// Borrow a book
app.post('/api/books/:bookId/borrow', authenticateToken, (req, res) => {
    const { bookId } = req.params;
    const { days = 30 } = req.body;

    db.get(
        'SELECT COUNT(*) as count FROM borrowings WHERE user_id = ? AND returned_date IS NULL',
        [req.user.id],
        (err, row) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (row.count >= 3) {
                console.log(`📚 BORROW LIMIT REACHED: ${req.user.name} (${req.user.email}) tried to borrow book ID ${bookId}`);
                return res.status(400).json({ error: 'Borrow limit reached (3 books)' });
            }

            db.get(
                `SELECT b.*, 
                        (b.quantity - IFNULL((
                        SELECT COUNT(*) 
                        FROM borrowings br 
                        WHERE br.book_id = b.id AND br.returned_date IS NULL
                    ), 0)) as available
                FROM books b WHERE b.id = ?`,
                [bookId],
                (err, book) => {
                    if (err) return res.status(500).json({ error: 'Database error' });
                    if (!book) return res.status(404).json({ error: 'Book not found' });
                    if (book.available <= 0) {
                        console.log(`📚 BOOK NOT AVAILABLE: ${req.user.name} tried to borrow "${book.title}" but it's out of stock`);
                        return res.status(400).json({ error: 'Book not available' });
                    }

                    const borrowedDate = new Date().toISOString().split('T')[0];
                    const dueDate = new Date();
                    dueDate.setDate(dueDate.getDate() + parseInt(days));
                    const dueDateStr = dueDate.toISOString().split('T')[0];

                    db.run(
                        'INSERT INTO borrowings (book_id, user_id, borrowed_date, due_date) VALUES (?, ?, ?, ?)',
                        [bookId, req.user.id, borrowedDate, dueDateStr],
                        function(err) {
                            if (err) {
                                console.error('Error borrowing book:', err);
                                return res.status(500).json({ error: 'Error borrowing book' });
                            }
                            
                            // ✅ ADDED: Log book borrowing
                            console.log(`📚 BOOK BORROWED: "${book.title}" by ${req.user.name} (${req.user.email}) | Due: ${dueDateStr} | Borrow ID: ${this.lastID} | Time: ${new Date().toLocaleString()}`);
                            
                            res.json({ message: 'Book borrowed successfully', borrowId: this.lastID });
                        }
                    );
                }
            );
        }
    );
});

// Return a book
app.post('/api/books/:bookId/return', authenticateToken, (req, res) => {
    const { bookId } = req.params;

    const returnDate = new Date().toISOString().split('T')[0];

    // First get book details for logging
    db.get('SELECT title FROM books WHERE id = ?', [bookId], (err, book) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        db.run(
            'UPDATE borrowings SET returned_date = ? WHERE book_id = ? AND user_id = ? AND returned_date IS NULL',
            [returnDate, bookId, req.user.id],
            function(err) {
                if (err) {
                    console.error('Error returning book:', err);
                    return res.status(500).json({ error: 'Error returning book' });
                }
                if (this.changes === 0) return res.status(404).json({ error: 'No active borrowing found' });
                
                // ✅ ADDED: Log book return
                const bookTitle = book ? book.title : `ID ${bookId}`;
                console.log(`📗 BOOK RETURNED: "${bookTitle}" by ${req.user.name} (${req.user.email}) | Time: ${new Date().toLocaleString()}`);
                
                res.json({ message: 'Book returned successfully' });
            }
        );
    });
});

// Delete a book
app.delete('/api/books/:bookId', authenticateToken, (req, res) => {
    if (req.user.role !== 'librarian') {
        console.log(`🚫 UNAUTHORIZED BOOK DELETE ATTEMPT: ${req.user.name} (${req.user.email}) tried to delete book ID ${req.params.bookId}`);
        return res.status(403).json({ error: 'Only librarians can delete books' });
    }

    const { bookId } = req.params;

    // First get book details for logging
    db.get('SELECT title, author FROM books WHERE id = ?', [bookId], (err, book) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        db.get(
            'SELECT COUNT(*) as count FROM borrowings WHERE book_id = ? AND returned_date IS NULL',
            [bookId],
            (err, row) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                if (row.count > 0) {
                    console.log(`🚫 BOOK DELETE BLOCKED: "${book.title}" has active borrowings`);
                    return res.status(400).json({ error: 'Cannot delete book with active borrowings' });
                }

                db.run('DELETE FROM books WHERE id = ?', [bookId], function(err) {
                    if (err) {
                        console.error('Error deleting book:', err);
                        return res.status(500).json({ error: 'Error deleting book' });
                    }
                    if (this.changes === 0) return res.status(404).json({ error: 'Book not found' });
                    
                    // ✅ ADDED: Log book deletion
                    console.log(`🗑️  BOOK DELETED: "${book.title}" by ${book.author} | Deleted by: ${req.user.name} | Time: ${new Date().toLocaleString()}`);
                    
                    res.json({ message: 'Book deleted successfully' });
                });
            }
        );
    });
});

// Get library statistics
app.get('/api/statistics', authenticateToken, (req, res) => {
    if (req.user.role !== 'librarian') {
        console.log(`📊 UNAUTHORIZED STATS ACCESS: ${req.user.name} (${req.user.email}) tried to access statistics`);
        return res.status(403).json({ error: 'Access denied' });
    }

    const queries = [
        'SELECT COUNT(*) as count FROM books',
        `SELECT SUM(b.quantity - IFNULL((
            SELECT COUNT(*) 
            FROM borrowings br 
            WHERE br.book_id = b.id AND br.returned_date IS NULL
        ), 0)) as available FROM books b`,
        'SELECT COUNT(*) as count FROM borrowings WHERE returned_date IS NULL',
        'SELECT COUNT(*) as count FROM users',
        'SELECT COUNT(*) as count FROM borrowings WHERE due_date < date("now") AND returned_date IS NULL',
        'SELECT COUNT(*) as count FROM borrowings'
    ];

    const stats = {};
    const statNames = ['totalBooks', 'availableBooks', 'borrowedBooks', 'totalUsers', 'overdueBooks', 'totalBorrowings'];

    let completed = 0;

    queries.forEach((query, index) => {
        db.get(query, (err, row) => {
            if (err) {
                console.error('Error getting stats:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            stats[statNames[index]] = row.count || row.available || 0;
            completed++;

            if (completed === queries.length) {
                // ✅ ADDED: Log statistics access
                console.log(`📊 STATISTICS ACCESSED: ${req.user.name} viewed library stats | Time: ${new Date().toLocaleString()}`);
                res.json(stats);
            }
        });
    });
});

// Get all borrowings (for librarian)
app.get('/api/borrowings', authenticateToken, (req, res) => {
    if (req.user.role !== 'librarian') {
        console.log(`📋 UNAUTHORIZED BORROWINGS ACCESS: ${req.user.name} (${req.user.email}) tried to access all borrowings`);
        return res.status(403).json({ error: 'Access denied' });
    }

    const query = `
        SELECT br.*, b.title as book_title, b.author, u.name as user_name
        FROM borrowings br
        JOIN books b ON br.book_id = b.id
        JOIN users u ON br.user_id = u.id
        ORDER BY br.borrowed_date DESC
    `;

    db.all(query, (err, borrowings) => {
        if (err) {
            console.error('Error fetching all borrowings:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        // ✅ ADDED: Log borrowings access
        console.log(`📋 ALL BORROWINGS ACCESSED: ${req.user.name} viewed ${borrowings.length} borrowing records | Time: ${new Date().toLocaleString()}`);
        
        res.json(borrowings);
    });
});

// Serve the main page for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Only start the server if this file is run directly (not when required by tests)
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🚀 Server running on http://localhost:${PORT}`);
        console.log(`📝 Logging enabled for user actions, book operations, and system events`);
        console.log(`⏰ Server started at: ${new Date().toLocaleString()}`);
    });
}

// Export the app for testing
module.exports = app;
