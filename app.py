import pyodbc
import hashlib
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'super-secret-key-for-advanced-voting-system'

# --- Database Connection ---
def get_db_connection():
    # Connect to the new database: SecureVoteDB
    return pyodbc.connect(
        'DRIVER={ODBC Driver 17 for SQL Server};'
        'SERVER=localhost\\SQLEXPRESS;'
        'DATABASE=SecureVoteDB;'
        'Trusted_Connection=yes;'
    )

# --- Security and Helpers ---
def hash_data(*args):
    """Hashes data using SHA256 for integrity checks."""
    combined = "|".join(str(arg) for arg in args).encode()
    return hashlib.sha256(combined).hexdigest()

def row_to_dict(cursor, row):
    """Converts a single pyodbc row to a dictionary."""
    if row is None: return None
    columns = [column[0].lower() for column in cursor.description]
    return dict(zip(columns, row))

def rows_to_dicts(cursor):
    """Converts all pyodbc rows from a fetchall() to a list of dictionaries."""
    columns = [column[0].lower() for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]

# --- Decorators for Access Control ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'voter_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'voter_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if not session.get('is_admin', False):
            flash('You do not have permission to access the admin panel.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- Public & Authentication Routes ---

@app.route('/')
def home():
    return render_template('public/index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']; email = request.form['email']
        password = request.form['password']; dob = request.form['dob']
        
        # Automatic admin promotion for the first admin account
        is_admin = 1 if email.lower() == 'admin@securevote.com' else 0
        
        hashed_pwd = hash_data(password)
        conn = get_db_connection(); cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO Voter (FullName, Email, HashedPassword, DateOfBirth, IsAdmin) VALUES (?, ?, ?, ?, ?)",
                full_name, email, hashed_pwd, dob, is_admin
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except pyodbc.IntegrityError:
            flash('Email already registered. Please use a different email or log in.', 'danger')
        finally:
            cursor.close(); conn.close()
    return render_template('public/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']; password = request.form['password']
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT * FROM Voter WHERE Email = ?", email)
        voter = row_to_dict(cursor, cursor.fetchone())
        cursor.close(); conn.close()
        
        if voter and voter['hashedpassword'] == hash_data(password):
            session['voter_id'] = voter['voterid']; session['email'] = voter['email']
            session['is_admin'] = bool(voter['isadmin']); session['is_eligible'] = bool(voter['iseligible'])
            
            flash('Login successful!', 'success')
            if session['is_admin']:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    return render_template('public/login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

# --- Voter-Facing Routes ---

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection(); cursor = conn.cursor()
    
    # Get current voter info
    cursor.execute("SELECT * FROM Voter WHERE VoterID = ?", session['voter_id'])
    voter = row_to_dict(cursor, cursor.fetchone())
    
    # Get ongoing or upcoming elections
    cursor.execute("SELECT * FROM Election WHERE EndDate >= GETDATE() ORDER BY StartDate ASC")
    elections = rows_to_dicts(cursor)

    # Get elections the user has already voted in
    cursor.execute("SELECT ElectionID FROM Vote WHERE VoterID = ?", session['voter_id'])
    voted_elections = [row['electionid'] for row in rows_to_dicts(cursor)]
    
    cursor.close(); conn.close()
    
    if voter is None: # Should not happen if logged in, but a good safe-guard
        session.clear()
        return redirect(url_for('login'))
        
    return render_template('voter/dashboard.html', voter=voter, elections=elections, voted_elections=voted_elections)

@app.route('/election/<int:election_id>')
@login_required
def view_election(election_id):
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT * FROM Election WHERE ElectionID = ?", election_id)
    election = row_to_dict(cursor, cursor.fetchone())
    
    if not election:
        flash(f'Election with ID #{election_id} not found!', 'danger')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT * FROM Candidate WHERE ElectionID = ?", election_id)
    candidates = rows_to_dicts(cursor)
    cursor.execute("SELECT 1 FROM Vote WHERE VoterID = ? AND ElectionID = ?", session['voter_id'], election_id)
    has_voted = cursor.fetchone() is not None
    cursor.close(); conn.close()

    now = datetime.now()
    is_election_active = election['startdate'] <= now <= election['enddate']
    
    return render_template('voter/election_details.html', election=election, candidates=candidates, has_voted=has_voted, is_election_active=is_election_active)

@app.route('/vote/<int:election_id>', methods=['POST'])
@login_required
def cast_vote(election_id):
    if not session.get('is_eligible', False):
        flash('You are not eligible to vote!', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM Vote WHERE VoterID = ? AND ElectionID = ?", session['voter_id'], election_id)
    if cursor.fetchone():
        flash('You have already voted in this election!', 'danger')
        cursor.close(); conn.close()
        return redirect(url_for('dashboard'))

    candidate_id = request.form.get('candidate_id')
    if not candidate_id:
        flash('You must select a candidate to vote.', 'danger')
        return redirect(url_for('view_election', election_id=election_id))

    # The secure, stable hash (without timestamp) for verification
    vote_hash = hash_data(session['voter_id'], election_id, candidate_id)
    
    try:
        sql = "INSERT INTO Vote (VoterID, CandidateID, ElectionID, HashReference) OUTPUT INSERTED.VoteID VALUES (?, ?, ?, ?)"
        vote_id = cursor.execute(sql, session['voter_id'], int(candidate_id), election_id, vote_hash).fetchval()
        conn.commit()
        flash(f"Vote cast successfully! Your unique Vote ID is: {vote_id}. Keep this safe to verify your vote later.", 'success')
    except pyodbc.Error as e:
        conn.rollback()
        flash(f"An error occurred: {e}", "danger")
    finally:
        cursor.close(); conn.close()

    return redirect(url_for('dashboard'))


@app.route('/verify_vote', methods=['GET', 'POST'])
def verify_vote():
    result = None
    if request.method == 'POST':
        vote_id = request.form.get('vote_id')
        if not vote_id or not vote_id.isdigit():
            flash("Please enter a valid numeric Vote ID.", 'warning')
            return render_template('public/verify_vote.html', result=result)

        conn = get_db_connection(); cursor = conn.cursor()
        query = """
            SELECT v.VoteID, v.VoterID, v.CandidateID, v.ElectionID, v.HashReference, v.VotedAt,
                   c.FullName as CandidateName, e.Title as ElectionTitle
            FROM Vote v
            JOIN Candidate c ON v.CandidateID = c.CandidateID
            JOIN Election e ON v.ElectionID = e.ElectionID
            WHERE v.VoteID = ?
        """
        cursor.execute(query, vote_id)
        vote_details = row_to_dict(cursor, cursor.fetchone())
        cursor.close(); conn.close()
        
        if vote_details:
            recalculated_hash = hash_data(vote_details['voterid'], vote_details['electionid'], vote_details['candidateid'])
            if recalculated_hash == vote_details['hashreference']:
                result = {'status': 'success', 'message': 'Vote integrity VERIFIED!', 'details': vote_details}
            else:
                result = {'status': 'danger', 'message': 'TAMPERING DETECTED! Stored hash does not match calculated hash.', 'details': vote_details}
        else:
            result = {'status': 'warning', 'message': f'Vote with ID #{vote_id} was not found.'}
            
    return render_template('public/verify_vote.html', result=result)


# --- ADMIN PANEL ROUTES ---

@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection(); cursor = conn.cursor()
    stats = {}
    stats['voters'] = cursor.execute("SELECT COUNT(*) FROM Voter").fetchval()
    stats['elections'] = cursor.execute("SELECT COUNT(*) FROM Election").fetchval()
    stats['votes'] = cursor.execute("SELECT COUNT(*) FROM Vote").fetchval()
    
    cursor.execute("""
        SELECT TOP 5 e.Title, COUNT(v.VoteID) as VoteCount
        FROM Election e
        LEFT JOIN Vote v ON e.ElectionID = v.ElectionID
        GROUP BY e.ElectionID, e.Title
        ORDER BY VoteCount DESC
    """)
    top_elections = rows_to_dicts(cursor)
    
    cursor.close(); conn.close()
    return render_template('admin/dashboard.html', stats=stats, top_elections=top_elections)

@app.route('/admin/elections')
@admin_required
def admin_manage_elections():
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("""
        SELECT e.*, (SELECT COUNT(*) FROM Candidate WHERE ElectionID = e.ElectionID) as CandidateCount,
               (SELECT COUNT(*) FROM Vote WHERE ElectionID = e.ElectionID) as VoteCount
        FROM Election e
        ORDER BY e.StartDate DESC
    """)
    elections = rows_to_dicts(cursor)
    cursor.close(); conn.close()
    return render_template('admin/elections.html', elections=elections)

@app.route('/admin/election/new', methods=['GET', 'POST'])
@admin_required
def admin_create_election():
    if request.method == 'POST':
        title = request.form['title']; description = request.form['description']
        start_date = request.form['start_date']; end_date = request.form['end_date']
        
        try:
            start_dt = datetime.fromisoformat(start_date)
            end_dt = datetime.fromisoformat(end_date)
            if start_dt >= end_dt:
                flash('End date must be after the start date.', 'danger')
                return render_template('admin/election_form.html', form_title="Create New Election")
            
            conn = get_db_connection(); cursor = conn.cursor()
            cursor.execute("INSERT INTO Election (Title, Description, StartDate, EndDate) VALUES (?, ?, ?, ?)",
                           title, description, start_dt, end_dt)
            conn.commit(); cursor.close(); conn.close()
            flash('Election created successfully!', 'success')
            return redirect(url_for('admin_manage_elections'))
        except (ValueError, pyodbc.Error) as e:
            flash(f'Error creating election: {e}', 'danger')

    return render_template('admin/election_form.html', form_title="Create New Election", election=None)

@app.route('/admin/election/edit/<int:election_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_election(election_id):
    conn = get_db_connection(); cursor = conn.cursor()
    if request.method == 'POST':
        title = request.form['title']; description = request.form['description']
        start_date = request.form['start_date']; end_date = request.form['end_date']
        try:
            start_dt = datetime.fromisoformat(start_date); end_dt = datetime.fromisoformat(end_date)
            cursor.execute("UPDATE Election SET Title = ?, Description = ?, StartDate = ?, EndDate = ? WHERE ElectionID = ?",
                           title, description, start_dt, end_dt, election_id)
            conn.commit();
            flash('Election updated successfully!', 'success')
            return redirect(url_for('admin_manage_elections'))
        except (ValueError, pyodbc.Error) as e:
            flash(f'Error updating election: {e}', 'danger')
        finally:
             cursor.close(); conn.close()
    
    cursor.execute("SELECT * FROM Election WHERE ElectionID = ?", election_id)
    election = row_to_dict(cursor, cursor.fetchone())
    cursor.close(); conn.close()
    if not election:
        flash('Election not found.', 'danger'); return redirect(url_for('admin_manage_elections'))
        
    return render_template('admin/election_form.html', form_title="Edit Election", election=election)


@app.route('/admin/election/delete/<int:election_id>', methods=['POST'])
@admin_required
def admin_delete_election(election_id):
    # Note: On a real-world system, you might 'soft delete' (set an 'is_deleted' flag) 
    # instead of hard deleting to preserve vote records.
    # The `ON DELETE CASCADE` for Candidates will remove them automatically.
    # Votes are preserved since they don't have cascade delete.
    conn = get_db_connection(); cursor = conn.cursor()
    try:
        # Check for votes before deleting
        cursor.execute("SELECT 1 FROM Vote WHERE ElectionID = ?", election_id)
        if cursor.fetchone():
            flash('Cannot delete an election that has votes. Consider archiving instead.', 'danger')
            return redirect(url_for('admin_manage_elections'))

        cursor.execute("DELETE FROM Election WHERE ElectionID = ?", election_id)
        conn.commit()
        flash('Election and its candidates have been deleted.', 'success')
    except pyodbc.Error as e:
        flash(f"Error deleting election: {e}", "danger")
    finally:
        cursor.close(); conn.close()
    return redirect(url_for('admin_manage_elections'))

@app.route('/admin/election/<int:election_id>/candidates')
@admin_required
def admin_manage_candidates(election_id):
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT Title FROM Election WHERE ElectionID = ?", election_id)
    election_title = cursor.fetchval()
    if not election_title:
        flash("Election not found", "danger")
        return redirect(url_for('admin_manage_elections'))

    cursor.execute("SELECT * FROM Candidate WHERE ElectionID = ?", election_id)
    candidates = rows_to_dicts(cursor)
    cursor.close(); conn.close()
    return render_template('admin/candidates.html', candidates=candidates, election_id=election_id, election_title=election_title)

@app.route('/admin/election/<int:election_id>/candidate/add', methods=['GET', 'POST'])
@admin_required
def admin_add_candidate(election_id):
    if request.method == 'POST':
        full_name = request.form['full_name']; party = request.form.get('party', '')
        bio = request.form.get('bio', '')
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("INSERT INTO Candidate (ElectionID, FullName, Party, Bio) VALUES (?, ?, ?, ?)",
                       election_id, full_name, party, bio)
        conn.commit(); cursor.close(); conn.close()
        flash('Candidate added successfully.', 'success')
        return redirect(url_for('admin_manage_candidates', election_id=election_id))

    return render_template('admin/candidate_form.html', form_title="Add New Candidate", election_id=election_id, candidate=None)
    
@app.route('/admin/candidate/edit/<int:candidate_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_candidate(candidate_id):
    conn = get_db_connection(); cursor = conn.cursor()
    if request.method == 'POST':
        full_name = request.form['full_name']; party = request.form.get('party', '')
        bio = request.form.get('bio', '')
        election_id = request.form['election_id']
        cursor.execute("UPDATE Candidate SET FullName = ?, Party = ?, Bio = ? WHERE CandidateID = ?",
                       full_name, party, bio, candidate_id)
        conn.commit(); cursor.close(); conn.close()
        flash('Candidate updated successfully.', 'success')
        return redirect(url_for('admin_manage_candidates', election_id=election_id))

    cursor.execute("SELECT * FROM Candidate WHERE CandidateID = ?", candidate_id)
    candidate = row_to_dict(cursor, cursor.fetchone())
    cursor.close(); conn.close()
    if not candidate:
        flash("Candidate not found.", 'danger'); return redirect(url_for('admin_dashboard'))

    return render_template('admin/candidate_form.html', form_title="Edit Candidate", candidate=candidate, election_id=candidate['electionid'])


@app.route('/admin/candidate/delete/<int:candidate_id>', methods=['POST'])
@admin_required
def admin_delete_candidate(candidate_id):
    conn = get_db_connection(); cursor = conn.cursor()
    # First get the election_id so we can redirect back correctly
    cursor.execute("SELECT ElectionID FROM Candidate WHERE CandidateID = ?", candidate_id)
    result = cursor.fetchone()
    if not result:
        flash("Candidate not found.", 'danger'); cursor.close(); conn.close()
        return redirect(url_for('admin_dashboard'))
    election_id = result[0]

    # Now, delete the candidate
    cursor.execute("DELETE FROM Candidate WHERE CandidateID = ?", candidate_id)
    conn.commit(); cursor.close(); conn.close()
    flash('Candidate deleted successfully.', 'success')
    return redirect(url_for('admin_manage_candidates', election_id=election_id))


@app.route('/admin/voters')
@admin_required
def admin_manage_voters():
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT VoterID, FullName, Email, RegisteredAt, IsEligible, IsAdmin FROM Voter ORDER BY RegisteredAt DESC")
    voters = rows_to_dicts(cursor)
    cursor.close(); conn.close()
    return render_template('admin/voters.html', voters=voters)


@app.route('/admin/votes')
@admin_required
def admin_view_votes():
    conn = get_db_connection(); cursor = conn.cursor()
    # A more detailed query for the admin panel
    query = """
        SELECT 
            v.VoteID, v.VotedAt, v.HashReference,
            vtr.FullName as VoterName, vtr.Email as VoterEmail,
            c.FullName as CandidateName,
            e.Title as ElectionTitle
        FROM Vote v
        JOIN Voter vtr ON v.VoterID = vtr.VoterID
        JOIN Candidate c ON v.CandidateID = c.CandidateID
        JOIN Election e ON v.ElectionID = e.ElectionID
        ORDER BY v.VotedAt DESC;
    """
    cursor.execute(query)
    votes = rows_to_dicts(cursor)
    cursor.close(); conn.close()
    return render_template('admin/votes.html', votes=votes)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
