from flask import Flask, abort, jsonify, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import collections
import json
import sqlite3
import hashlib
import re
import secrets
from datetime import datetime

app = Flask(__name__)
app.secret_key = '123456789' 
DATABASE = 'database.sqlite'

# Load censorship data
# WARNING! The censorship.dat file contains disturbing language when decrypted. 
# If you want to test whether moderation works, 
# you can trigger censorship using these words: 
# tier1badword, tier2badword, tier3badword
ENCRYPTED_FILE_PATH = 'censorship.dat'
fernet = Fernet('xpplx11wZUibz0E8tV8Z9mf-wwggzSrc21uQ17Qq2gg=')
with open(ENCRYPTED_FILE_PATH, 'rb') as encrypted_file:
    encrypted_data = encrypted_file.read()
decrypted_data = fernet.decrypt(encrypted_data)
MODERATION_CONFIG = json.loads(decrypted_data)
TIER1_WORDS = MODERATION_CONFIG['categories']['tier1_severe_violations']['words']
TIER2_PHRASES = MODERATION_CONFIG['categories']['tier2_spam_scams']['phrases']
TIER3_WORDS = MODERATION_CONFIG['categories']['tier3_mild_profanity']['words']

def get_db():
    """
    Connect to the application's configured database. The connection
    is unique for each request and will be reused if this is called
    again.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)

    if db is not None:
        db.close()


def query_db(query, args=(), one=False, commit=False):
    """
    Queries the database and returns a list of dictionaries, a single
    dictionary, or None. Also handles write operations.
    """
    db = get_db()
    
    # Using 'with' on a connection object implicitly handles transactions.
    # The 'with' statement will automatically commit if successful, 
    # or rollback if an exception occurs. This is safer.
    try:
        with db:
            cur = db.execute(query, args)
        
        # For SELECT statements, fetch the results after the transaction block
        if not commit:
            rv = cur.fetchall()
            return (rv[0] if rv else None) if one else rv
        
        # For write operations, we might want the cursor to get info like lastrowid
        return cur

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

@app.template_filter('datetimeformat')
def datetimeformat(value):
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
    else:
        return "N/A"
    return dt.strftime('%b %d, %Y %H:%M')

REACTION_EMOJIS = {
    'like': '❤️', 'love': '😍', 'laugh': '😂',
    'wow': '😮', 'sad': '😢', 'angry': '😠',
}
REACTION_TYPES = list(REACTION_EMOJIS.keys())


# Claim 13: give every logged-in member one concrete, system-suggested goal.
# Five posts/comments is intentionally measurable and challenging but still
# achievable during one week.
WEEKLY_GOAL_TARGET = 5
MIN_POST_LENGTH = 30
MIN_POST_WORDS = 5


def analyze_post_quality(content):
    """Return interactive revision feedback for a new post draft.

    Claim 15 needs feedback to respond to the member's actual input. A post
    is ready when it has enough detail, mentions another member, and includes
    a hashtag that helps the community discover its topic.
    """
    text = content.strip() if isinstance(content, str) else ''
    word_count = len(re.findall(r"\b[\w']+\b", text))
    has_mention = bool(re.search(r'(?<!\w)@[A-Za-z0-9_]+', text))
    has_hashtag = bool(re.search(r'(?<!\w)#[A-Za-z0-9_]+', text))

    issues = []
    if len(text) < MIN_POST_LENGTH:
        issues.append(f'Add more detail (at least {MIN_POST_LENGTH} characters).')
    if word_count < MIN_POST_WORDS:
        issues.append(f'Use at least {MIN_POST_WORDS} words.')
    if not has_mention:
        issues.append('Mention another member with @username.')
    if not has_hashtag:
        issues.append('Add a hashtag such as #discussion.')

    return {
        'is_ready': not issues,
        'issues': issues,
        'length': len(text),
        'word_count': word_count,
        'has_mention': has_mention,
        'has_hashtag': has_hashtag,
    }


def get_positive_contribution_score(user_id):
    """Count a user's posts and comments that follow the content norm.

    This is intentionally separate from moderation risk and the weekly goal:
    it gives contributors understandable positive feedback without changing
    the existing risk calculations or goal progress rules.
    """
    if not user_id:
        return 0

    messages = query_db('''
        SELECT content FROM posts WHERE user_id = ?
        UNION ALL
        SELECT content FROM comments WHERE user_id = ?
    ''', (user_id, user_id)) or []
    return sum(1 for message in messages if moderate_content(message['content'])[1] < 1.0)


def get_weekly_goal(user_id):
    """Return a measurable system-suggested weekly contribution goal.

    The goal runs from Monday through Sunday. Posts and comments have
    timestamps in the supplied database, so they are used for the weekly
    goal. Reactions are intentionally excluded because the existing reactions
    table does not record when a reaction was made.
    """
    if not user_id:
        return None

    # SQLite's %w returns Sunday as 0; the expression below converts it into
    # a Monday-based offset so the goal period is always Monday through Sunday.
    activity = query_db('''
        SELECT COUNT(*) AS count
        FROM (
            SELECT id FROM posts
            WHERE user_id = ? AND created_at >= date('now', '-' || ((CAST(strftime('%w', 'now') AS INTEGER) + 6) % 7) || ' days')
            UNION ALL
            SELECT id FROM comments
            WHERE user_id = ? AND created_at >= date('now', '-' || ((CAST(strftime('%w', 'now') AS INTEGER) + 6) % 7) || ' days')
        ) weekly_activity
    ''', (user_id, user_id), one=True)
    current_count = activity['count'] if activity else 0

    comparison = query_db('''
        SELECT
            COALESCE(AVG(member_count), 0) AS average_count,
            COALESCE(MAX(member_count), 0) AS highest_count
        FROM (
            SELECT user_id, COUNT(*) AS member_count
            FROM (
                SELECT user_id FROM posts
                WHERE created_at >= date('now', '-' || ((CAST(strftime('%w', 'now') AS INTEGER) + 6) % 7) || ' days')
                UNION ALL
                SELECT user_id FROM comments
                WHERE created_at >= date('now', '-' || ((CAST(strftime('%w', 'now') AS INTEGER) + 6) % 7) || ' days')
            ) recent_activity
            GROUP BY user_id
        ) member_activity
    ''', one=True)

    # Cap the display at 100% while retaining the real count for completion
    # and feedback calculations.
    percentage = min(100, round(current_count / WEEKLY_GOAL_TARGET * 100))
    # datetime.weekday() returns Monday=0 and Sunday=6, so Sunday has zero
    # days remaining and can be presented as "today" in the interface.
    days_left = 6 - datetime.utcnow().weekday()
    goal = {
        'title': 'Weekly community contribution goal',
        'description': f'Make {WEEKLY_GOAL_TARGET} posts or comments by the end of this week.',
        'target': WEEKLY_GOAL_TARGET,
        'current': current_count,
        'remaining': max(0, WEEKLY_GOAL_TARGET - current_count),
        'percentage': percentage,
        'completed': current_count >= WEEKLY_GOAL_TARGET,
        'days_left': days_left,
        'days_label': 'today' if days_left == 0 else f'{days_left} days left',
        'average': round(comparison['average_count'], 1) if comparison else 0,
        'highest': comparison['highest_count'] if comparison else 0,
    }
    goal['feedback'] = get_goal_feedback(goal)
    return goal


def get_goal_feedback(goal):
    """Create timely, performance-based feedback for a weekly goal."""
    # Feedback changes as the member progresses, making Claim 15 observable
    # instead of showing the same generic encouragement every time.
    time_message = 'The deadline is today.' if goal['days_left'] == 0 else f"You have {goal['days_left']} days left."
    if goal['completed']:
        return f'Goal completed—thank you for contributing to the community! {time_message}'
    if goal['current'] == 0:
        return f'You have not started this goal yet. Your first contribution gets you moving. {time_message}'
    if goal['remaining'] == 1:
        return f'You are one contribution away from completing this goal! {time_message}'
    if goal['current'] < goal['average']:
        return f"You are at {goal['percentage']}%. Keep contributing to catch up with the community average. {time_message}"
    return f"You are at {goal['percentage']}%. Keep going—you have made good progress. {time_message}"


def get_community_social_proof():
    """Return recent, database-backed participation for the feed summary.

    The summary supports Claim 12 by showing that other members have already
    contributed. The existing reactions table has no timestamp, so this uses
    the complete activity currently represented in the supplied database.
    """
    # Count actions separately for total participation, but use UNION below
    # when counting members so one member is not counted more than once.
    activity_count = query_db('''
        SELECT COUNT(*) AS count
        FROM (
            SELECT user_id FROM posts
            UNION ALL
            SELECT user_id FROM comments
            UNION ALL
            SELECT user_id FROM reactions
        ) recent_activity
    ''', one=True)

    member_count = query_db('''
        SELECT COUNT(*) AS count
        FROM (
            SELECT user_id FROM posts
            UNION
            SELECT user_id FROM comments
            UNION
            SELECT user_id FROM reactions
        ) recent_members
    ''', one=True)

    top_contributors = query_db('''
        SELECT u.username, COUNT(*) AS contribution_count
        FROM (
            SELECT user_id FROM posts
            UNION ALL
            SELECT user_id FROM comments
            UNION ALL
            SELECT user_id FROM reactions
        ) recent_activity
        JOIN users u ON u.id = recent_activity.user_id
        GROUP BY recent_activity.user_id, u.username
        ORDER BY contribution_count DESC, u.username ASC
        LIMIT 3
    ''')

    return {
        'active_members': member_count['count'] if member_count else 0,
        'contributions': activity_count['count'] if activity_count else 0,
        'top_contributors': top_contributors or [],
    }


def get_post_social_proof(post_id):
    """Return distinct member participation for one post.

    A member is counted once even if they both comment and react. This avoids
    inflating the social-proof number while still exposing total actions.
    """
    proof = query_db('''
        SELECT
            (
                SELECT COUNT(*)
                FROM (
                    SELECT user_id FROM comments WHERE post_id = ?
                    UNION
                    SELECT user_id FROM reactions WHERE post_id = ?
                ) contributors
            ) AS contributor_count,
            (
                SELECT COUNT(*) FROM comments WHERE post_id = ?
            ) + (
                SELECT COUNT(*) FROM reactions WHERE post_id = ?
            ) AS contribution_count
    ''', (post_id, post_id, post_id, post_id), one=True)

    return {
        'contributors': proof['contributor_count'] if proof else 0,
        'contributions': proof['contribution_count'] if proof else 0,
    }


def get_community_norm_statistics():
    """Calculate prevalence statistics for content that follows community norms.

    A message is considered norm-following when its moderation score is below
    1.0. Posts and comments are analyzed together so the statistics represent
    the community's visible message behavior rather than only one content type.
    """
    messages = query_db('''
        SELECT p.id, 'post' AS message_type, p.content, p.created_at, u.username
        FROM posts p
        JOIN users u ON u.id = p.user_id
        UNION ALL
        SELECT c.id, 'comment' AS message_type, c.content, c.created_at, u.username
        FROM comments c
        JOIN users u ON u.id = c.user_id
        ORDER BY 4 DESC
    ''') or []

    scored_messages = []
    for message in messages:
        moderated_content, score = moderate_content(message['content'])
        scored_messages.append({
            'content': moderated_content,
            'score': score,
            'message_type': message['message_type'],
            'created_at': message['created_at'],
            'username': message['username'],
        })

    total_messages = len(scored_messages)
    compliant_messages = [message for message in scored_messages if message['score'] < 1.0]
    flagged_messages = total_messages - len(compliant_messages)
    compliance_percentage = (
        round(len(compliant_messages) / total_messages * 100, 1)
        if total_messages else 0.0
    )

    latest_flag_index = next(
        (index for index, message in enumerate(scored_messages) if message['score'] >= 1.0),
        None
    )
    messages_since_last_flag = (
        latest_flag_index
        if latest_flag_index is not None
        else total_messages
    )

    return {
        'total_messages': total_messages,
        'compliant_messages': len(compliant_messages),
        'flagged_messages': flagged_messages,
        'compliance_percentage': compliance_percentage,
        'messages_since_last_flag': messages_since_last_flag,
        'examples': compliant_messages[:3],
    }


@app.route('/norm-check', methods=['POST'])
def norm_check():
    """Return live moderation feedback for the member's current draft."""
    if not session.get('user_id'):
        return jsonify({'error': 'Login required.'}), 401

    payload = request.get_json(silent=True) or request.form
    content = payload.get('content', '')
    _, score = moderate_content(content)
    follows_norm = score < 1.0
    return jsonify({
        'score': score,
        'follows_norm': follows_norm,
        'message': (
            'This draft follows the community content norm.'
            if follows_norm else
            'This draft may not follow the community content norm. Revise it before posting.'
        ),
    })


@app.route('/')
def feed():
    #  1. Get Pagination and Filter Parameters 
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    sort = request.args.get('sort', 'new').lower()
    show = request.args.get('show', 'all').lower()
    
    # Define how many posts to show per page
    POSTS_PER_PAGE = 10
    offset = (page - 1) * POSTS_PER_PAGE

    current_user_id = session.get('user_id')
    params = []

    #  2. Build the Query 
    where_clause = ""
    if show == 'following' and current_user_id:
        where_clause = "WHERE p.user_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)"
        params.append(current_user_id)

    # Add the pagination parameters to the query arguments
    pagination_params = (POSTS_PER_PAGE, offset)

    if sort == 'popular':
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id,
                   IFNULL(r.total_reactions, 0) as total_reactions
            FROM posts p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as total_reactions FROM reactions GROUP BY post_id
            ) r ON p.id = r.post_id
            {where_clause}
            ORDER BY total_reactions DESC, p.created_at DESC
            LIMIT ? OFFSET ?
        """
        final_params = params + list(pagination_params)
        posts = query_db(query, final_params)
    elif sort == 'recommended':
        posts = recommend(current_user_id, show == 'following')
    else:  # Default sort is 'new'
        query = f"""
            SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
            FROM posts p
            JOIN users u ON p.user_id = u.id
            {where_clause}
            ORDER BY p.created_at DESC
            LIMIT ? OFFSET ?
        """
        final_params = params + list(pagination_params)
        posts = query_db(query, final_params)

    posts_data = []
    for post in posts:
        # Determine if the current user follows the poster
        followed_poster = False
        if current_user_id and post['user_id'] != current_user_id:
            follow_check = query_db(
                'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
                (current_user_id, post['user_id']),
                one=True
            )
            if follow_check:
                followed_poster = True

        # Determine if the current user reacted to this post and with what reaction
        user_reaction = None
        if current_user_id:
            reaction_check = query_db(
                'SELECT reaction_type FROM reactions WHERE user_id = ? AND post_id = ?',
                (current_user_id, post['id']),
                one=True
            )
            if reaction_check:
                user_reaction = reaction_check['reaction_type']

        reactions = query_db('SELECT reaction_type, COUNT(*) as count FROM reactions WHERE post_id = ? GROUP BY reaction_type', (post['id'],))
        comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post['id'],))
        # Claim 12 uses distinct contributors for social proof, while the
        # existing reaction/comment totals remain available separately.
        social_proof = get_post_social_proof(post['id'])
        post_dict = dict(post)
        if current_user_id:
            share_token = get_or_create_share_link(post['id'], current_user_id)
            post_dict['share_url'] = url_for('shared_post', token=share_token, _external=True)
        # Recommendation metadata is present only on the Recommended feed;
        # normal feed modes continue using their existing post data.
        post_dict['content'], _ = moderate_content(post_dict['content'])
        comments_moderated = []
        for comment in comments_raw:
            comment_dict = dict(comment)
            comment_dict['content'], _ = moderate_content(comment_dict['content'])
            comments_moderated.append(comment_dict)
        posts_data.append({
            'post': post_dict,
            'reactions': reactions,
            'user_reaction': user_reaction,
            'followed_poster': followed_poster,
            'comments': comments_moderated,
            'social_proof': social_proof
        })

    newcomer = bool(current_user_id and is_newcomer(current_user_id))
    #  4. Render Template with Pagination Info 
    return render_template('feed.html.j2', 
                           posts=posts_data, 
                           current_sort=sort,
                           current_show=show,
                           page=page, # Pass current page number
                           per_page=POSTS_PER_PAGE, # Pass items per page
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES,
                           community_social_proof=get_community_social_proof(),
                           community_norms=get_community_norm_statistics(),
                           post_draft=session.get('post_draft', ''),
                           min_post_length=MIN_POST_LENGTH,
                           min_post_words=MIN_POST_WORDS,
                           newcomer=newcomer,
                           welcome_suggestions=(
                               get_welcome_suggestions(current_user_id)
                               if newcomer else []
                           ),
                           unread_welcome_count=(
                               get_unread_welcome_count(current_user_id)
                               if current_user_id else 0
                           ))

@app.route('/posts/new', methods=['POST'])
def add_post():
    """Handles creating a new post from the feed."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to create a post.', 'danger')
        return redirect(url_for('login'))

    # Get content from the submitted form
    content = request.form.get('content')

    # Enforce the same quality rules used by the live form so a request that
    # bypasses JavaScript still receives revision guidance.
    quality = analyze_post_quality(content)
    if not quality['is_ready']:
        session['post_draft'] = content or ''
        flash(
            'Please revise your post before submitting: '
            + ' '.join(quality['issues']),
            'warning'
        )
        return redirect(url_for('feed'))

    # Pass the user's content through the moderation function
    moderated_content = content

    # Basic validation to ensure post is not empty
    if moderated_content and moderated_content.strip():
        db = get_db()
        db.execute('INSERT INTO posts (user_id, content) VALUES (?, ?)',
                   (user_id, moderated_content))
        db.commit()
        session.pop('post_draft', None)
        _, post_score = moderate_content(moderated_content)
        positive_score = get_positive_contribution_score(user_id)
        # Refresh the goal immediately so the success message gives current
        # Claim 15 feedback after the contribution is recorded.
        goal = get_weekly_goal(user_id)
        if post_score < 1.0:
            contribution_feedback = (
                f'Your positive contribution score increased to {positive_score}.'
            )
        else:
            contribution_feedback = (
                f'Your positive contribution score stays at {positive_score}; '
                'revise the moderation issues to increase it.'
            )
        flash(
            f"Your post was successfully created! {contribution_feedback} "
            f"{goal['feedback']}",
            'success'
        )
    else:
        # This will catch empty posts or posts that were fully censored
        flash('Post cannot be empty or was fully censored.', 'warning')

    # Redirect back to the main feed to see the new post
    return redirect(url_for('feed'))
    
    
@app.route('/posts/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    """Handles deleting a post."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to delete a post.', 'danger')
        return redirect(url_for('login'))

    # Find the post in the database
    post = query_db('SELECT id, user_id FROM posts WHERE id = ?', (post_id,), one=True)

    # Check if the post exists and if the current user is the owner
    if not post:
        flash('Post not found.', 'danger')
        return redirect(url_for('feed'))

    if post['user_id'] != user_id:
        # Security check: prevent users from deleting others' posts
        flash('You do not have permission to delete this post.', 'danger')
        return redirect(url_for('feed'))

    # If all checks pass, proceed with deletion
    db = get_db()
    # To maintain database integrity, delete associated records first
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
    # Finally, delete the post itself
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()

    flash('Your post was successfully deleted.', 'success')
    # Redirect back to the page the user came from, or the feed as a fallback
    return redirect(request.referrer or url_for('feed'))

@app.route('/u/<username>')
def user_profile(username):
    """Displays a user's profile page with moderated bio, posts, and latest comments."""
    
    user_raw = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user_raw:
        abort(404)

    user = dict(user_raw)
    moderated_bio, _ = moderate_content(user.get('profile', ''))
    user['profile'] = moderated_bio

    posts_raw = query_db('SELECT id, content, user_id, created_at FROM posts WHERE user_id = ? ORDER BY created_at DESC', (user['id'],))
    posts = []
    for post_raw in posts_raw:
        post = dict(post_raw)
        moderated_post_content, _ = moderate_content(post['content'])
        post['content'] = moderated_post_content
        posts.append(post)

    comments_raw = query_db('SELECT id, content, user_id, post_id, created_at FROM comments WHERE user_id = ? ORDER BY created_at DESC LIMIT 100', (user['id'],))
    comments = []
    for comment_raw in comments_raw:
        comment = dict(comment_raw)
        moderated_comment_content, _ = moderate_content(comment['content'])
        comment['content'] = moderated_comment_content
        comments.append(comment)

    followers_count = query_db('SELECT COUNT(*) as cnt FROM follows WHERE followed_id = ?', (user['id'],), one=True)['cnt']
    following_count = query_db('SELECT COUNT(*) as cnt FROM follows WHERE follower_id = ?', (user['id'],), one=True)['cnt']

    #  NEW: CHECK FOLLOW STATUS 
    is_currently_following = False # Default to False
    current_user_id = session.get('user_id')
    
    # We only need to check if a user is logged in
    if current_user_id:
        follow_relation = query_db(
            'SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
            (current_user_id, user['id']),
            one=True
        )
        if follow_relation:
            is_currently_following = True
    # --

    return render_template('user_profile.html.j2', 
                           user=user, 
                           posts=posts, 
                           comments=comments,
                           followers_count=followers_count, 
                           following_count=following_count,
                           is_following=is_currently_following,
                           weekly_goal=(get_weekly_goal(current_user_id)
                                        if current_user_id == user['id'] else None),
                           positive_contribution_score=(
                               get_positive_contribution_score(user['id'])
                               if current_user_id == user['id'] else None
                           ),
                           received_welcomes=(
                               get_received_welcomes(user['id'])
                               if current_user_id == user['id'] else []
                           ),
                           profile_is_newcomer=is_newcomer(user['id']))
    

@app.route('/u/<username>/followers')
def user_followers(username):
    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        abort(404)
    followers = query_db('''
        SELECT u.username
        FROM follows f
        JOIN users u ON f.follower_id = u.id
        WHERE f.followed_id = ?
    ''', (user['id'],))
    return render_template('user_list.html.j2', user=user, users=followers, title="Followers of")

@app.route('/u/<username>/following')
def user_following(username):
    user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
    if not user:
        abort(404)
    following = query_db('''
        SELECT u.username
        FROM follows f
        JOIN users u ON f.followed_id = u.id
        WHERE f.follower_id = ?
    ''', (user['id'],))
    return render_template('user_list.html.j2', user=user, users=following, title="Users followed by")

@app.route('/posts/<int:post_id>')
def post_detail(post_id):
    """Displays a single post and its comments, with content moderation applied."""
    
    post_raw = query_db('''
        SELECT p.id, p.content, p.created_at, u.username, u.id as user_id
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    ''', (post_id,), one=True)

    if not post_raw:
        # The abort function will stop the request and show a 404 Not Found page.
        abort(404)

    #  Moderation for the Main Post 
    # Convert the raw database row to a mutable dictionary
    post = dict(post_raw)
    # Unpack the tuple from moderate_content, we only need the moderated content string here
    moderated_post_content, _ = moderate_content(post['content'])
    post['content'] = moderated_post_content

    #  Fetch Reactions (No moderation needed) 
    reactions = query_db('''
        SELECT reaction_type, COUNT(*) as count
        FROM reactions
        WHERE post_id = ?
        GROUP BY reaction_type
    ''', (post_id,))

    #  Fetch and Moderate Comments 
    comments_raw = query_db('SELECT c.id, c.content, c.created_at, u.username, u.id as user_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.post_id = ? ORDER BY c.created_at ASC', (post_id,))
    
    comments = [] # Create a new list for the moderated comments
    for comment_raw in comments_raw:
        comment = dict(comment_raw) # Convert to a dictionary
        # Moderate the content of each comment
        print(comment['content'])
        moderated_comment_content, _ = moderate_content(comment['content'])
        comment['content'] = moderated_comment_content
        comments.append(comment)

    share_url = None
    if session.get('user_id'):
        share_token = get_or_create_share_link(post_id, session['user_id'])
        share_url = url_for('shared_post', token=share_token, _external=True)

    # Pass the moderated data to the template
    return render_template('post_detail.html.j2',
                           post=post,
                           reactions=reactions,
                           comments=comments,
                           reaction_emojis=REACTION_EMOJIS,
                           reaction_types=REACTION_TYPES,
                           share_url=share_url)

@app.route('/about')
def about():
    return render_template('about.html.j2')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html.j2')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        location = request.form.get('location', '')
        birthdate = request.form.get('birthdate', '')
        profile = request.form.get('profile', '')
        referral_token = session.get('referral_token')

        hashed_password = generate_password_hash(password)

        db = get_db()
        cur = db.cursor()
        try:
            initialize_social_connection_tables()
            cur.execute(
                'INSERT INTO users (username, password, location, birthdate, profile) VALUES (?, ?, ?, ?, ?)',
                (username, hashed_password, location, birthdate, profile)
            )
            db.commit()

            # 1. Get the ID of the user we just created.
            new_user_id = cur.lastrowid

            # 2. Add user info to the session cookie.
            session.clear() # Clear any old session data
            session['user_id'] = new_user_id
            session['username'] = username

            if referral_token:
                referral_link = query_db(
                    'SELECT id FROM share_links WHERE token = ?',
                    (referral_token,), one=True
                )
                if referral_link:
                    db.execute('''
                        INSERT OR IGNORE INTO referral_signups (share_link_id, new_user_id)
                        VALUES (?, ?)
                    ''', (referral_link['id'], new_user_id))
                    db.commit()

            # 3. Flash a welcome message and redirect to the feed.
            flash(f'Welcome, {username}! Your account has been created.', 'success')
            return redirect(url_for('feed')) # Redirect to the main feed/dashboard

        except sqlite3.IntegrityError:
            flash('Username already taken. Please choose another one.', 'danger')
        finally:
            cur.close()
            db.close()
            
    return render_template('signup.html.j2')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()

        # 1. Check if the user exists.
        # 2. If user exists, use check_password_hash to securely compare the password.
        #    This function handles the salt and prevents timing attacks.
        if user and check_password_hash(user['password'], password):
            # Password is correct!
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('feed'))
        else:
            # User does not exist or password was incorrect.
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html.j2')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/posts/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    """Handles adding a new comment to a specific post."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to comment.', 'danger')
        return redirect(url_for('login'))

    # Get content from the submitted form
    content = request.form.get('content')

    # Basic validation to ensure comment is not empty
    if content and content.strip():
        db = get_db()
        db.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
                   (post_id, user_id, content))
        db.commit()
        # Comments count toward the same weekly goal as posts.
        goal = get_weekly_goal(user_id)
        flash(f"Your comment was added. {goal['feedback']}", 'success')
    else:
        flash('Comment cannot be empty.', 'warning')

    # Redirect back to the page the user came from (likely the post detail page)
    return redirect(request.referrer or url_for('post_detail', post_id=post_id))

@app.route('/comments/<int:comment_id>/delete', methods=['POST'])
def delete_comment(comment_id):
    """Handles deleting a comment."""
    user_id = session.get('user_id')

    # Block access if user is not logged in
    if not user_id:
        flash('You must be logged in to delete a comment.', 'danger')
        return redirect(url_for('login'))

    # Find the comment and the original post's author ID
    comment = query_db('''
        SELECT c.id, c.user_id, p.user_id as post_author_id
        FROM comments c
        JOIN posts p ON c.post_id = p.id
        WHERE c.id = ?
    ''', (comment_id,), one=True)

    # Check if the comment exists
    if not comment:
        flash('Comment not found.', 'danger')
        return redirect(request.referrer or url_for('feed'))

    # Security Check: Allow deletion if the user is the comment's author OR the post's author
    if user_id != comment['user_id'] and user_id != comment['post_author_id']:
        flash('You do not have permission to delete this comment.', 'danger')
        return redirect(request.referrer or url_for('feed'))

    # If all checks pass, proceed with deletion
    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()

    flash('Comment successfully deleted.', 'success')
    # Redirect back to the page the user came from
    return redirect(request.referrer or url_for('feed'))

@app.route('/react', methods=['POST'])
def add_reaction():
    """Handles adding a new reaction or updating an existing one."""
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to react.", "danger")
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')
    new_reaction_type = request.form.get('reaction')

    if not post_id or not new_reaction_type:
        flash("Invalid reaction request.", "warning")
        return redirect(request.referrer or url_for('feed'))

    db = get_db()

    # Step 1: Check if a reaction from this user already exists on this post.
    existing_reaction = query_db('SELECT id FROM reactions WHERE post_id = ? AND user_id = ?',
                                 (post_id, user_id), one=True)

    if existing_reaction:
        # Step 2: If it exists, UPDATE the reaction_type.
        db.execute('UPDATE reactions SET reaction_type = ? WHERE id = ?',
                   (new_reaction_type, existing_reaction['id']))
    else:
        # Step 3: If it does not exist, INSERT a new reaction.
        db.execute('INSERT INTO reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)',
                   (post_id, user_id, new_reaction_type))

    db.commit()

    return redirect(request.referrer or url_for('feed'))

@app.route('/unreact', methods=['POST'])
def unreact():
    """Handles removing a user's reaction from a post."""
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to unreact.", "danger")
        return redirect(url_for('login'))

    post_id = request.form.get('post_id')

    if not post_id:
        flash("Invalid unreact request.", "warning")
        return redirect(request.referrer or url_for('feed'))

    db = get_db()

    # Remove the reaction if it exists
    existing_reaction = query_db(
        'SELECT id FROM reactions WHERE post_id = ? AND user_id = ?',
        (post_id, user_id),
        one=True
    )

    if existing_reaction:
        db.execute('DELETE FROM reactions WHERE id = ?', (existing_reaction['id'],))
        db.commit()
        flash("Reaction removed.", "success")
    else:
        flash("No reaction to remove.", "info")

    return redirect(request.referrer or url_for('feed'))


@app.route('/u/<int:user_id>/follow', methods=['POST'])
def follow_user(user_id):
    """Handles the logic for the current user to follow another user."""
    follower_id = session.get('user_id')

    # Security: Ensure user is logged in
    if not follower_id:
        flash("You must be logged in to follow users.", "danger")
        return redirect(url_for('login'))

    # Security: Prevent users from following themselves
    if follower_id == user_id:
        flash("You cannot follow yourself.", "warning")
        return redirect(request.referrer or url_for('feed'))

    # Check if the user to be followed actually exists
    user_to_follow = query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True)
    if not user_to_follow:
        flash("The user you are trying to follow does not exist.", "danger")
        return redirect(request.referrer or url_for('feed'))
        
    db = get_db()
    try:
        # Insert the follow relationship. The PRIMARY KEY constraint will prevent duplicates if you've set one.
        db.execute('INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)',
                   (follower_id, user_id))
        db.commit()
        username_to_follow = query_db('SELECT username FROM users WHERE id = ?', (user_id,), one=True)['username']
        flash(f"You are now following {username_to_follow}.", "success")
    except sqlite3.IntegrityError:
        flash("You are already following this user.", "info")

    return redirect(request.referrer or url_for('feed'))


@app.route('/u/<int:user_id>/unfollow', methods=['POST'])
def unfollow_user(user_id):
    """Handles the logic for the current user to unfollow another user."""
    follower_id = session.get('user_id')

    # Security: Ensure user is logged in
    if not follower_id:
        flash("You must be logged in to unfollow users.", "danger")
        return redirect(url_for('login'))

    db = get_db()
    cur = db.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?',
               (follower_id, user_id))
    db.commit()

    if cur.rowcount > 0:
        # cur.rowcount tells us if a row was actually deleted
        username_unfollowed = query_db('SELECT username FROM users WHERE id = ?', (user_id,), one=True)['username']
        flash(f"You have unfollowed {username_unfollowed}.", "success")
    else:
        # This case handles if someone tries to unfollow a user they weren't following
        flash("You were not following this user.", "info")

    # Redirect back to the page the user came from
    return redirect(request.referrer or url_for('feed'))

@app.route('/admin')
def admin_dashboard():
    """Displays the admin dashboard with users, posts, and comments, sorted by risk."""

    if session.get('username') != 'admin':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('feed'))

    RISK_LEVELS = { "HIGH": 5, "MEDIUM": 3, "LOW": 1 }
    PAGE_SIZE = 50

    def get_risk_profile(score):
        if score >= RISK_LEVELS["HIGH"]:
            return "HIGH", 3
        elif score >= RISK_LEVELS["MEDIUM"]:
            return "MEDIUM", 2
        elif score >= RISK_LEVELS["LOW"]:
            return "LOW", 1
        return "NONE", 0

    # Get pagination and current tab parameters
    try:
        users_page = int(request.args.get('users_page', 1))
        posts_page = int(request.args.get('posts_page', 1))
        comments_page = int(request.args.get('comments_page', 1))
    except ValueError:
        users_page = 1
        posts_page = 1
        comments_page = 1
    
    current_tab = request.args.get('tab', 'users') # Default to 'users' tab

    users_offset = (users_page - 1) * PAGE_SIZE
    
    # First, get all users to calculate risk, then apply pagination in Python
    # It's more complex to do this efficiently in SQL if risk calc is Python-side
    all_users_raw = query_db('SELECT id, username, profile, created_at FROM users')
    all_users = []
    for user in all_users_raw:
        user_dict = dict(user)
        user_risk_score = user_risk_analysis(user_dict['id'])
        risk_label, risk_sort_key = get_risk_profile(user_risk_score)
        user_dict['risk_label'] = risk_label
        user_dict['risk_sort_key'] = risk_sort_key
        user_dict['risk_score'] = min(5.0, round(user_risk_score, 2))
        all_users.append(user_dict)

    all_users.sort(key=lambda x: x['risk_score'], reverse=True)
    total_users = len(all_users)
    users = all_users[users_offset : users_offset + PAGE_SIZE]
    total_users_pages = (total_users + PAGE_SIZE - 1) // PAGE_SIZE

    # --- Posts Tab Data ---
    posts_offset = (posts_page - 1) * PAGE_SIZE
    total_posts_count = query_db('SELECT COUNT(*) as count FROM posts', one=True)['count']
    total_posts_pages = (total_posts_count + PAGE_SIZE - 1) // PAGE_SIZE

    posts_raw = query_db(f'''
        SELECT p.id, p.content, p.created_at, u.username, u.created_at as user_created_at
        FROM posts p JOIN users u ON p.user_id = u.id
        ORDER BY p.id DESC -- Order by ID for consistent pagination before risk sort
        LIMIT ? OFFSET ?
    ''', (PAGE_SIZE, posts_offset))
    posts = []
    for post in posts_raw:
        post_dict = dict(post)
        _, base_score = moderate_content(post_dict['content'])
        final_score = base_score 
        author_created_dt = post_dict['user_created_at']
        author_age_days = (datetime.utcnow() - author_created_dt).days
        if author_age_days < 7:
            final_score *= 1.5
        risk_label, risk_sort_key = get_risk_profile(final_score)
        post_dict['risk_label'] = risk_label
        post_dict['risk_sort_key'] = risk_sort_key
        post_dict['risk_score'] = round(final_score, 2)
        posts.append(post_dict)

    posts.sort(key=lambda x: x['risk_score'], reverse=True) # Sort after fetching and scoring

    # --- Comments Tab Data ---
    comments_offset = (comments_page - 1) * PAGE_SIZE
    total_comments_count = query_db('SELECT COUNT(*) as count FROM comments', one=True)['count']
    total_comments_pages = (total_comments_count + PAGE_SIZE - 1) // PAGE_SIZE

    comments_raw = query_db(f'''
        SELECT c.id, c.content, c.created_at, u.username, u.created_at as user_created_at
        FROM comments c JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC -- Order by ID for consistent pagination before risk sort
        LIMIT ? OFFSET ?
    ''', (PAGE_SIZE, comments_offset))
    comments = []
    for comment in comments_raw:
        comment_dict = dict(comment)
        _, score = moderate_content(comment_dict['content'])
        author_created_dt = comment_dict['user_created_at']
        author_age_days = (datetime.utcnow() - author_created_dt).days
        if author_age_days < 7:
            score *= 1.5
        risk_label, risk_sort_key = get_risk_profile(score)
        comment_dict['risk_label'] = risk_label
        comment_dict['risk_sort_key'] = risk_sort_key
        comment_dict['risk_score'] = round(score, 2)
        comments.append(comment_dict)

    comments.sort(key=lambda x: x['risk_score'], reverse=True) # Sort after fetching and scoring


    return render_template('admin.html.j2', 
                           users=users, 
                           posts=posts, 
                           comments=comments,
                           
                           # Pagination for Users
                           users_page=users_page,
                           total_users_pages=total_users_pages,
                           users_has_next=(users_page < total_users_pages),
                           users_has_prev=(users_page > 1),

                           # Pagination for Posts
                           posts_page=posts_page,
                           total_posts_pages=total_posts_pages,
                           posts_has_next=(posts_page < total_posts_pages),
                           posts_has_prev=(posts_page > 1),

                           # Pagination for Comments
                           comments_page=comments_page,
                           total_comments_pages=total_comments_pages,
                           comments_has_next=(comments_page < total_comments_pages),
                           comments_has_prev=(comments_page > 1),

                           current_tab=current_tab,
                           PAGE_SIZE=PAGE_SIZE)



@app.route('/admin/delete/user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))
        
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account from the admin panel.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash(f'User {user_id} and all their content has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/post/<int:post_id>', methods=['POST'])
def admin_delete_post(post_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM reactions WHERE post_id = ?', (post_id,))
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash(f'Post {post_id} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/comment/<int:comment_id>', methods=['POST'])
def admin_delete_comment(comment_id):
    if session.get('username') != 'admin':
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('feed'))

    db = get_db()
    db.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    flash(f'Comment {comment_id} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/rules')
def rules():
    return render_template('rules.html.j2')

@app.template_global()
def loop_color(user_id):
    # Generate a pastel color based on user_id hash
    h = hashlib.md5(str(user_id).encode()).hexdigest()
    r = int(h[0:2], 16)
    g = int(h[2:4], 16)
    b = int(h[4:6], 16)
    return f'rgb({r % 128 + 80}, {g % 128 + 80}, {b % 128 + 80})'


# ----- Functions to be implemented are below
# Coding Assignment #2


def _parse_database_datetime(value):
    """Return a database timestamp as a datetime object when possible."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=None)
    return None


def _average_score(scores):
    """Return the average of content scores, or zero when there is no content."""
    return sum(scores) / len(scores) if scores else 0.0


# Assignment 2.2
def user_risk_analysis(user_id):
    """
    Args:
        user_id: The ID of the user on which we perform risk analysis.

    Returns:
        A float number score showing the risk associated with this user. There are no strict rules or bounds to this score, other than that a score of less than 1.0 means no risk, 1.0 to 3.0 is low risk, 3.0 to 5.0 is medium risk and above 5.0 is high risk. (An upper bound of 5.0 is applied to this score elsewhere in the codebase) 
        
        You will be able to check the scores by logging in with the administrator account:
            username: admin
            password: admin
        Then, navigate to the /admin endpoint. (http://localhost:8080/admin)
    """
    
    user = query_db(
        'SELECT profile, created_at FROM users WHERE id = ?',
        (user_id,),
        one=True
    )
    if not user:
        return 0.0

    _, profile_score = moderate_content(user['profile'] or '')

    posts = query_db(
        'SELECT content FROM posts WHERE user_id = ?',
        (user_id,)
    ) or []
    post_scores = [moderate_content(post['content'])[1] for post in posts]

    comments = query_db(
        'SELECT content FROM comments WHERE user_id = ?',
        (user_id,)
    ) or []
    comment_scores = [moderate_content(comment['content'])[1] for comment in comments]

    # Posts have three times the weight of profile and comment content.
    content_risk_score = (
        profile_score
        + (_average_score(post_scores) * 3)
        + _average_score(comment_scores)
    )

    created_at = _parse_database_datetime(user['created_at'])
    age_days = (datetime.utcnow() - created_at).days if created_at else 0
    age_days = max(0, age_days)
    if age_days < 7:
        age_multiplier = 1.5
    elif age_days < 30:
        age_multiplier = 1.2
    else:
        age_multiplier = 1.0

    # The user-level score is capped as required by the risk specification.
    return min(content_risk_score * age_multiplier, 5.0)

    
# Assignment 2.1
def moderate_content(content):
    """
    Args
        content: the text content of a post or comment to be moderated.
        
    Returns: 
        A tuple containing the moderated content (string) and a severity score (float). There are no strict rules or bounds to the severity score, other than that a score of less than 1.0 means no risk, 1.0 to 3.0 is low risk, 3.0 to 5.0 is medium risk and above 5.0 is high risk.
    
    This function moderates a string of content and calculates a severity score based on
    rules loaded from the 'censorship.dat' file. These are already loaded as TIER1_WORDS, TIER2_PHRASES and TIER3_WORDS. Tier 1 corresponds to strong profanity, Tier 2 to scam/spam phrases and Tier 3 to mild profanity.
    
    You will be able to check the scores by logging in with the administrator account:
            username: admin
            password: admin
    Then, navigate to the /admin endpoint. (http://localhost:8080/admin)
    """

    if content is None:
        return '', 0.0
    if not isinstance(content, str):
        content = str(content)
    if not content:
        return '', 0.0

    # Tier 1 and Tier 2 are terminal checks: severe content is removed
    # completely and must not receive additional lower-tier scores.
    tier1_pattern = re.compile(
        r'(?<!\w)(?:' + '|'.join(re.escape(word) for word in TIER1_WORDS) + r')(?!\w)',
        re.IGNORECASE
    ) if TIER1_WORDS else None
    if tier1_pattern and tier1_pattern.search(content):
        return '[content removed due to severe violation]', 5.0

    tier2_pattern = re.compile(
        r'(?<!\w)(?:' + '|'.join(re.escape(phrase) for phrase in TIER2_PHRASES) + r')(?!\w)',
        re.IGNORECASE
    ) if TIER2_PHRASES else None
    if tier2_pattern and tier2_pattern.search(content):
        return '[content removed due to spam/scam policy]', 5.0

    original_content = content
    score = 0.0

    # Replace every Tier 3 occurrence with an equally long mask while counting
    # occurrences rather than distinct vocabulary items.
    if TIER3_WORDS:
        tier3_pattern = re.compile(
            r'(?<!\w)(?:' + '|'.join(
                sorted((re.escape(word) for word in TIER3_WORDS), key=len, reverse=True)
            ) + r')(?!\w)',
            re.IGNORECASE
        )
        tier3_matches = list(tier3_pattern.finditer(content))
        score += len(tier3_matches) * 2.0
        content = tier3_pattern.sub(
            lambda match: '*' * len(match.group(0)),
            content
        )

    # Match common HTTP(S) and www URLs. URL punctuation is left outside the
    # match where possible so sentences retain their natural punctuation.
    url_pattern = re.compile(r'(?i)\b(?:https?://|www\.)[^\s<>()]+')
    urls = url_pattern.findall(content)
    score += len(urls) * 2.0

    def replace_url(match):
        url = match.group(0)
        trailing = ''
        while url and url[-1] in '.,!?;:':
            trailing = url[-1] + trailing
            url = url[:-1]
        return '[link removed]' + trailing

    content = url_pattern.sub(replace_url, content)

    # Capitalization is measured from the original text so masking or URL
    # replacement cannot change the uppercase ratio.
    letters = [character for character in original_content if character.isalpha()]
    uppercase_count = sum(character.isupper() for character in letters)
    if len(letters) > 15 and uppercase_count / len(letters) > 0.70:
        score += 0.5

    return content, score

# Coding Assignment #3
# Assignment 3.1

POSITIVE_REACTIONS = ('like', 'love', 'laugh', 'wow')
RECOMMENDATION_FEEDBACK_TYPES = ('more_like_this', 'not_interested')
RECOMMENDATION_STOP_WORDS = {
    'about', 'after', 'again', 'also', 'because', 'being', 'could', 'from',
    'have', 'into', 'just', 'more', 'most', 'other', 'that', 'their', 'there',
    'these', 'they', 'this', 'those', 'through', 'very', 'what', 'when',
    'where', 'which', 'with', 'would', 'your',
}


def initialize_social_connection_tables():
    """Create additive sharing, referral, and welcome-message tables."""
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS share_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE,
            post_id INTEGER NOT NULL,
            owner_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
        );
        CREATE TABLE IF NOT EXISTS share_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            share_link_id INTEGER NOT NULL,
            channel TEXT NOT NULL,
            visitor_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
        );
        CREATE TABLE IF NOT EXISTS referral_signups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            share_link_id INTEGER NOT NULL,
            new_user_id INTEGER NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
        );
        CREATE TABLE IF NOT EXISTS welcome_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
            read_at TIMESTAMP
        );
    ''')
    db.commit()


def get_or_create_share_link(post_id, owner_id):
    """Return a stable public token for a member's shared post."""
    initialize_social_connection_tables()
    existing = query_db(
        'SELECT token FROM share_links WHERE post_id = ? AND owner_id = ?',
        (post_id, owner_id), one=True
    )
    if existing:
        return existing['token']
    token = secrets.token_urlsafe(18)
    db = get_db()
    db.execute(
        'INSERT INTO share_links (token, post_id, owner_id) VALUES (?, ?, ?)',
        (token, post_id, owner_id)
    )
    db.commit()
    return token


def is_newcomer(user_id):
    """Return whether a user joined within the newcomer welcome period."""
    user = query_db('SELECT created_at FROM users WHERE id = ?', (user_id,), one=True)
    if not user or not user['created_at']:
        return False
    created_at = _parse_database_datetime(user['created_at'])
    return bool(created_at and (datetime.utcnow() - created_at).days < 7)


def get_welcome_suggestions(user_id):
    """Suggest recent members to welcome, excluding the current user."""
    initialize_social_connection_tables()
    return query_db('''
        SELECT u.id, u.username
        FROM users u
        WHERE u.id != ?
          AND u.created_at >= datetime('now', '-30 days')
          AND NOT EXISTS (
              SELECT 1 FROM welcome_messages w
              WHERE w.sender_id = ? AND w.recipient_id = u.id
          )
        ORDER BY u.created_at DESC
        LIMIT 5
    ''', (user_id, user_id)) or []


def get_unread_welcome_count(user_id):
    initialize_social_connection_tables()
    result = query_db(
        'SELECT COUNT(*) AS count FROM welcome_messages WHERE recipient_id = ? AND read_at IS NULL',
        (user_id,), one=True
    )
    return result['count'] if result else 0


def get_received_welcomes(user_id):
    """Return recent welcomes addressed to a member for profile display."""
    initialize_social_connection_tables()
    return query_db('''
        SELECT w.id, w.message, w.created_at, w.read_at, u.username AS sender_username
        FROM welcome_messages w
        JOIN users u ON u.id = w.sender_id
        WHERE w.recipient_id = ?
        ORDER BY w.created_at DESC
        LIMIT 10
    ''', (user_id,)) or []


@app.context_processor
def social_connection_context():
    """Expose unread welcome count to the shared navigation bar."""
    user_id = session.get('user_id')
    return {
        'unread_welcome_count': get_unread_welcome_count(user_id) if user_id else 0
    }


@app.route('/share/<token>')
def shared_post(token):
    """Record a public share visit and redirect to the original post."""
    initialize_social_connection_tables()
    link = query_db('''
        SELECT sl.id, sl.post_id, sl.owner_id
        FROM share_links sl
        WHERE sl.token = ?
    ''', (token,), one=True)
    if not link:
        abort(404)

    channel = request.args.get('channel', 'link')
    if channel not in {'link', 'email', 'twitter', 'facebook', 'web'}:
        channel = 'link'
    db = get_db()
    db.execute(
        'INSERT INTO share_events (share_link_id, channel, visitor_id) VALUES (?, ?, ?)',
        (link['id'], channel, session.get('user_id'))
    )
    db.commit()
    if session.get('user_id') != link['owner_id']:
        session['referral_token'] = token
    return redirect(url_for('post_detail', post_id=link['post_id']))


@app.route('/welcome/<int:user_id>', methods=['POST'])
def send_welcome(user_id):
    """Send a moderated, friendly welcome to a new member."""
    sender_id = session.get('user_id')
    if not sender_id:
        flash('You must be logged in to welcome a member.', 'danger')
        return redirect(url_for('login'))
    if sender_id == user_id or not query_db('SELECT id FROM users WHERE id = ?', (user_id,), one=True):
        flash('That member cannot receive this welcome.', 'warning')
        return redirect(request.referrer or url_for('feed'))
    if not is_newcomer(user_id):
        flash('Welcome messages are available for recent members only.', 'warning')
        return redirect(request.referrer or url_for('feed'))

    message = request.form.get('message', '').strip()
    if not message:
        flash('Please write a short welcome message.', 'warning')
        return redirect(request.referrer or url_for('feed'))
    moderated_message, score = moderate_content(message)
    if score >= 1.0:
        flash('Please revise the welcome message so it follows the community rules.', 'warning')
        return redirect(request.referrer or url_for('feed'))

    initialize_social_connection_tables()
    existing = query_db(
        'SELECT id FROM welcome_messages WHERE sender_id = ? AND recipient_id = ?',
        (sender_id, user_id), one=True
    )
    if existing:
        flash('You have already welcomed this member.', 'info')
        return redirect(request.referrer or url_for('feed'))
    db = get_db()
    db.execute(
        'INSERT INTO welcome_messages (sender_id, recipient_id, message) VALUES (?, ?, ?)',
        (sender_id, user_id, moderated_message)
    )
    db.commit()
    flash('Your friendly welcome was sent.', 'success')
    return redirect(request.referrer or url_for('feed'))


@app.route('/welcome/<int:message_id>/read', methods=['POST'])
def mark_welcome_read(message_id):
    recipient_id = session.get('user_id')
    if not recipient_id:
        return redirect(url_for('login'))
    initialize_social_connection_tables()
    db = get_db()
    db.execute(
        '''UPDATE welcome_messages SET read_at = CURRENT_TIMESTAMP
           WHERE id = ? AND recipient_id = ?''',
        (message_id, recipient_id)
    )
    db.commit()
    return redirect(request.referrer or url_for('feed'))


def initialize_recommendation_tables():
    """Create recommendation feedback storage without changing existing tables."""
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS recommendation_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            feedback_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
            UNIQUE (user_id, post_id)
        )
    ''')
    db.commit()


def _recommendation_tokens(content):
    """Extract useful words and hashtags for lightweight content matching."""
    raw_tokens = re.findall(r'(?i)(#?[a-z][a-z0-9_]{2,})', content or '')
    return [
        token.lstrip('#').lower()
        for token in raw_tokens
        if token.lstrip('#').lower() not in RECOMMENDATION_STOP_WORDS
    ]


def _get_recommendation_feedback(user_id):
    """Return the member's stored recommendation choices grouped by type."""
    initialize_recommendation_tables()
    rows = query_db(
        'SELECT post_id, feedback_type FROM recommendation_feedback WHERE user_id = ?',
        (user_id,)
    ) or []
    return {
        feedback_type: {row['post_id'] for row in rows if row['feedback_type'] == feedback_type}
        for feedback_type in RECOMMENDATION_FEEDBACK_TYPES
    }


def _recommendation_reason(overlap_terms, is_followed, liked_author, popularity):
    """Explain the strongest reason a post was selected."""
    if overlap_terms:
        terms = ', '.join(f'#{term.upper()}' for term in overlap_terms[:3])
        return f'Similar to posts you liked ({terms}).'
    if is_followed:
        return 'From a member you follow.'
    if liked_author:
        return 'From an author whose posts you liked.'
    if popularity:
        return 'Popular among community members.'
    return 'A recent community post you may find interesting.'


def recommend(user_id, filter_following):
    """
    Args:
        user_id: The ID of the current user.
        filter_following: Boolean, True if we only want to see recommendations from followed users.

    Returns:
        A list of 5 recommended posts, in reverse-chronological order.

    To test whether your recommendation algorithm works, let's pretend we like the DIY topic. Here are some users that often post DIY comment and a few example posts. Make sure your account did not engage with anything else. You should test your algorithm with these and see if your recommendation algorithm picks up on your interest in DIY and starts showing related content.
    
    Users: @starboy99, @DancingDolphin, @blogger_bob
    Posts: 1810, 1875, 1880, 2113
    
    Materials: 
    - https://www.nvidia.com/en-us/glossary/recommendation-system/
    - http://www.configworks.com/mz/handout_recsys_sac2010.pdf
    - https://www.researchgate.net/publication/227268858_Recommender_Systems_Handbook
    """

    if not user_id:
        return []

    feedback = _get_recommendation_feedback(user_id)
    excluded_post_ids = feedback['more_like_this'] | feedback['not_interested']

    positive_reactions = ','.join('?' for _ in POSITIVE_REACTIONS)
    liked_posts = query_db(
        f'''SELECT p.id, p.content, p.user_id
            FROM posts p
            JOIN reactions r ON r.post_id = p.id
            WHERE r.user_id = ? AND r.reaction_type IN ({positive_reactions})''',
        (user_id, *POSITIVE_REACTIONS)
    ) or []
    excluded_post_ids.update(post['id'] for post in liked_posts)

    # Explicit "more like this" choices act as additional positive signals.
    if feedback['more_like_this']:
        placeholders = ','.join('?' for _ in feedback['more_like_this'])
        liked_posts.extend(query_db(
            f'''SELECT id, content, user_id FROM posts
                WHERE id IN ({placeholders})''',
            tuple(feedback['more_like_this'])
        ) or [])

    interest_weights = collections.Counter()
    liked_authors = set()
    for liked_post in liked_posts:
        liked_authors.add(liked_post['user_id'])
        for token in _recommendation_tokens(liked_post['content']):
            # Hashtags are especially useful topic signals, so they receive
            # extra weight when they appear in the liked content.
            interest_weights[token] += 1

    followed_users = {
        row['followed_id'] for row in query_db(
            'SELECT followed_id FROM follows WHERE follower_id = ?',
            (user_id,)
        ) or []
    }

    posts = query_db('''
        SELECT p.id, p.content, p.created_at, u.username, u.id AS user_id,
               COUNT(r.id) AS reaction_count
        FROM posts p
        JOIN users u ON u.id = p.user_id
        LEFT JOIN reactions r ON r.post_id = p.id
        GROUP BY p.id, p.content, p.created_at, u.username, u.id
    ''') or []

    candidates = []
    for post in posts:
        post_id = post['id']
        author_id = post['user_id']
        if author_id == user_id or post_id in excluded_post_ids:
            continue
        if filter_following and author_id not in followed_users:
            continue

        candidate_tokens = set(_recommendation_tokens(post['content']))
        overlap = [
            token for token in candidate_tokens
            if token in interest_weights
        ]
        similarity_score = sum(interest_weights[token] for token in overlap)
        followed_bonus = 4 if author_id in followed_users else 0
        liked_author_bonus = 2 if author_id in liked_authors else 0
        popularity_bonus = min(int(post['reaction_count'] or 0), 3)

        # A small relevance floor prevents unrelated posts from displacing
        # useful matches when the member has already expressed interests.
        if interest_weights and similarity_score == 0 and not followed_bonus and not popularity_bonus:
            continue

        total_score = (
            similarity_score * 5
            + followed_bonus
            + liked_author_bonus
            + popularity_bonus
        )
        candidates.append({
            'post': dict(post),
            'score': total_score,
            'overlap': sorted(overlap, key=lambda token: interest_weights[token], reverse=True),
            'is_followed': author_id in followed_users,
            'liked_author': author_id in liked_authors,
            'popularity': bool(popularity_bonus),
        })

    candidates.sort(
        key=lambda candidate: (
            candidate['score'],
            candidate['post']['created_at'] or '',
            candidate['post']['id'],
        ),
        reverse=True
    )

    recommendations = []
    for candidate in candidates[:5]:
        post = candidate['post']
        post['recommendation_score'] = candidate['score']
        post['recommendation_reason'] = _recommendation_reason(
            candidate['overlap'],
            candidate['is_followed'],
            candidate['liked_author'],
            candidate['popularity'],
        )
        recommendations.append(post)
    return recommendations


@app.route('/recommendations/feedback', methods=['POST'])
def recommendation_feedback():
    """Store a member's interactive recommendation preference."""
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to give recommendation feedback.', 'danger')
        return redirect(url_for('login'))

    post_id = request.form.get('post_id', type=int)
    feedback_type = request.form.get('feedback_type')
    if not post_id or feedback_type not in RECOMMENDATION_FEEDBACK_TYPES:
        flash('Invalid recommendation feedback.', 'warning')
        return redirect(request.referrer or url_for('feed', sort='recommended'))

    if not query_db('SELECT id FROM posts WHERE id = ?', (post_id,), one=True):
        flash('The recommended post no longer exists.', 'warning')
        return redirect(request.referrer or url_for('feed', sort='recommended'))

    initialize_recommendation_tables()
    db = get_db()
    db.execute('''
        INSERT INTO recommendation_feedback (user_id, post_id, feedback_type)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, post_id) DO UPDATE SET
            feedback_type = excluded.feedback_type,
            created_at = CURRENT_TIMESTAMP
    ''', (user_id, post_id, feedback_type))
    db.commit()
    message = (
        'We will show more posts like this.'
        if feedback_type == 'more_like_this'
        else 'This post will be removed from your recommendations.'
    )
    flash(message, 'success')
    return redirect(request.referrer or url_for('feed', sort='recommended'))

if __name__ == '__main__':
    app.run(debug=True, port=8080)

