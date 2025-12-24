from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from models import db, User, TimeEntry, Checklist, ChecklistItem, ChecklistCompletion
from models import ChecklistItemCompletion, Animal, PhoneLog, Donation, ItemOut, AuditLog
from models import AnimalLocation, VetVisit, MaintenanceTicket, StaffNote, InventoryItem, InventoryTransaction
from config import Config
from datetime import datetime
from functools import wraps
from sqlalchemy import func, case
import json
import os

app = Flask(__name__)
app.config.from_object(Config)

# Initialize security
csrf = CSRFProtect(app)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You need administrator privileges to access this page.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission_name):
    """Decorator to check if user has specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not current_user.has_permission(permission_name):
                flash(f'You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_action(action, table_name=None, record_id=None, old_value=None, new_value=None):
    try:
        # Never log sensitive data like passwords
        if new_value and isinstance(new_value, dict):
            new_value = {k: v for k, v in new_value.items() if 'password' not in k.lower()}
        if old_value and isinstance(old_value, dict):
            old_value = {k: v for k, v in old_value.items() if 'password' not in k.lower()}
            
        audit = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            table_name=table_name,
            record_id=record_id,
            old_value=json.dumps(old_value) if old_value else None,
            new_value=json.dumps(new_value) if new_value else None,
            ip_address=request.remote_addr
        )
        db.session.add(audit)
        db.session.commit()
    except:
        pass

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.active and user.check_password(password):
            login_user(user)
            log_action('login')
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        elif user and not user.active:
            flash('This account has been deactivated. Contact an administrator.', 'error')
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_action('logout')
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.has_permission('view_dashboard'):
        flash('You do not have permission to view the dashboard.', 'error')
        return redirect(url_for('login'))
    
    active_entry = TimeEntry.query.filter_by(
        user_id=current_user.id,
        clock_out=None
    ).first()
    
    # Check if user can work multiple roles
    has_multiple_roles = current_user.role in ['employee', 'management', 'admin']
    
    # Get checklists
    today_checklists = []
    if current_user.has_permission('view_checklists'):
        # Filter by time of day if applicable
        current_hour = datetime.now().hour
        if current_hour < 12:
            time_filter = ['am', 'daily', 'weekly']
        else:
            time_filter = ['pm', 'daily', 'weekly']
        
        today_checklists = Checklist.query.filter(
            (Checklist.time_period.in_(time_filter)) | (Checklist.time_period == None)
        ).all()
    
    # Get recent animals
    recent_animals = []
    if current_user.has_permission('view_animals'):
        recent_animals = Animal.query.order_by(Animal.intake_date.desc()).limit(5).all()
    
    # Get completion status for checklists
    for checklist in today_checklists:
        last_completion = ChecklistCompletion.query.filter_by(
            checklist_id=checklist.id
        ).order_by(ChecklistCompletion.completed_at.desc()).first()
        checklist.last_completed = last_completion
    
    # Get unread staff notes count for management/admin/board
    unread_notes_count = 0
    if current_user.role in ['admin', 'management', 'board']:
        unread_notes_count = StaffNote.query.filter_by(is_read=False).count()
    
    # Get low stock items count
    low_stock_count = 0
    if current_user.has_permission('view_inventory'):
        low_stock_count = InventoryItem.query.filter(
            InventoryItem.reorder_point.isnot(None),
            InventoryItem.quantity <= InventoryItem.reorder_point
        ).count()
    
    return render_template('dashboard.html',
                         active_entry=active_entry,
                         has_multiple_roles=has_multiple_roles,
                         checklists=today_checklists,
                         recent_animals=recent_animals,
                         unread_notes_count=unread_notes_count,
                         low_stock_count=low_stock_count)

@app.route('/clock/in', methods=['POST'])
@login_required
def clock_in():
    if not current_user.has_permission('use_time_clock'):
        flash('You do not have permission to use the time clock.', 'error')
        return redirect(url_for('dashboard'))
    
    active = TimeEntry.query.filter_by(user_id=current_user.id, clock_out=None).first()
    if active:
        flash('You are already clocked in!', 'warning')
        return redirect(url_for('dashboard'))
    
    role_type = request.form.get('role_type', current_user.role)
    
    entry = TimeEntry(
        user_id=current_user.id, 
        clock_in=datetime.now(),
        role_type=role_type
    )
    db.session.add(entry)
    db.session.commit()
    log_action('clock_in', 'time_entry', entry.id, new_value={'role_type': role_type})
    flash(f'Clocked in successfully as {role_type}!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/clock/out', methods=['POST'])
@login_required
def clock_out():
    entry = TimeEntry.query.filter_by(user_id=current_user.id, clock_out=None).first()
    if not entry:
        flash('You are not clocked in!', 'error')
        return redirect(url_for('dashboard'))
    
    entry.clock_out = datetime.now()
    entry.calculate_hours()
    db.session.commit()
    log_action('clock_out', 'time_entry', entry.id)
    flash(f'Clocked out successfully! Hours worked: {entry.total_hours}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/clock/history')
@login_required
def clock_history():
    """
    For admins: Shows summary of all users with total hours separated by type
    For regular users: Shows their own history
    """
    if not current_user.has_permission('view_time_clock'):
        flash('You do not have permission to view time clock.', 'error')
        return redirect(url_for('dashboard'))
    
    if current_user.has_permission('view_all_time_entries'):
        # Admin view - show summary of all users with separated hours
        users_summary = db.session.query(
            User.id,
            User.username,
            User.role,
            func.sum(case((TimeEntry.role_type.in_(['employee', 'maintenance']), TimeEntry.total_hours), else_=0)).label('paid_hours'),
            func.sum(case((TimeEntry.role_type == 'volunteer', TimeEntry.total_hours), else_=0)).label('volunteer_hours'),
            func.sum(case((TimeEntry.role_type == 'employee', TimeEntry.total_hours), else_=0)).label('employee_hours'),
            func.sum(case((TimeEntry.role_type == 'maintenance', TimeEntry.total_hours), else_=0)).label('maintenance_hours'),
            func.sum(TimeEntry.total_hours).label('total_hours'),
            func.count(TimeEntry.id).label('total_entries')
        ).outerjoin(TimeEntry).group_by(User.id).all()
        
        return render_template('clock_summary.html', users_summary=users_summary)
    else:
        # Regular user view - show their own history
        page = request.args.get('page', 1, type=int)
        pagination = TimeEntry.query.filter_by(user_id=current_user.id).order_by(
            TimeEntry.clock_in.desc()
        ).paginate(page=page, per_page=25, error_out=False)
        
        return render_template('clock_history.html', pagination=pagination)

@app.route('/clock/user/<int:user_id>')
@login_required
def clock_user_detail(user_id):
    """
    Admin only: View detailed time entries for a specific user
    """
    if not current_user.has_permission('view_all_time_entries'):
        flash('Access denied.', 'error')
        return redirect(url_for('clock_history'))
    
    user = User.query.get_or_404(user_id)
    page = request.args.get('page', 1, type=int)
    
    # Get pagination for this user's entries
    pagination = TimeEntry.query.filter_by(user_id=user_id).order_by(
        TimeEntry.clock_in.desc()
    ).paginate(page=page, per_page=25, error_out=False)
    
    # Calculate total hours for this user
    total_hours = db.session.query(
        func.sum(TimeEntry.total_hours)
    ).filter_by(user_id=user_id).scalar() or 0
    
    return render_template('clock_user_detail.html', 
                         user=user, 
                         pagination=pagination,
                         total_hours=total_hours)

@app.route('/checklists')
@login_required
def checklists():
    if not current_user.has_permission('view_checklists'):
        flash('You do not have permission to view checklists.', 'error')
        return redirect(url_for('dashboard'))
    
    all_checklists = Checklist.query.all()
    
    # Add completion info
    for checklist in all_checklists:
        last_completion = ChecklistCompletion.query.filter_by(
            checklist_id=checklist.id
        ).order_by(ChecklistCompletion.completed_at.desc()).first()
        checklist.last_completed = last_completion
    
    return render_template('checklists.html', checklists=all_checklists)

@app.route('/checklist/<int:id>/complete', methods=['GET', 'POST'])
@login_required
def complete_checklist(id):
    if not current_user.has_permission('complete_checklists'):
        flash('You do not have permission to complete checklists.', 'error')
        return redirect(url_for('checklists'))
    
    checklist = Checklist.query.get_or_404(id)
    
    if request.method == 'POST':
        notes = request.form.get('notes', '')
        completion = ChecklistCompletion(
            checklist_id=id,
            user_id=current_user.id,
            notes=notes
        )
        db.session.add(completion)
        db.session.flush()
        
        for item in checklist.items:
            completed = request.form.get(f'item_{item.id}') == 'on'
            item_notes = request.form.get(f'notes_{item.id}', '')
            item_completion = ChecklistItemCompletion(
                completion_id=completion.id,
                item_id=item.id,
                completed=completed,
                notes=item_notes
            )
            db.session.add(item_completion)
        
        db.session.commit()
        log_action('complete_checklist', 'checklist_completion', completion.id)
        flash('Checklist completed successfully!', 'success')
        return redirect(url_for('checklists'))
    
    return render_template('complete_checklist.html', checklist=checklist)

@app.route('/checklist/<int:id>/history')
@login_required
def checklist_history(id):
    if not current_user.has_permission('view_checklists'):
        flash('You do not have permission to view checklist history.', 'error')
        return redirect(url_for('checklists'))
    
    checklist = Checklist.query.get_or_404(id)
    page = request.args.get('page', 1, type=int)
    
    pagination = ChecklistCompletion.query.filter_by(
        checklist_id=id
    ).order_by(ChecklistCompletion.completed_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    return render_template('checklist_history.html', checklist=checklist, pagination=pagination)

@app.route('/animals')
@login_required
def animals():
    if not current_user.has_permission('view_animals'):
        flash('You do not have permission to view animals.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'all')
    
    query = Animal.query
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    pagination = query.order_by(Animal.intake_date.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    
    return render_template('animals.html', pagination=pagination, status_filter=status_filter)

@app.route('/animal/<int:id>')
@login_required
def animal_detail(id):
    if not current_user.has_permission('view_animals'):
        flash('You do not have permission to view animals.', 'error')
        return redirect(url_for('dashboard'))
    
    animal = Animal.query.get_or_404(id)
    return render_template('animal_detail.html', animal=animal)

@app.route('/animal/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def animal_edit(id):
    if not current_user.has_permission('edit_animals'):
        flash('You do not have permission to edit animals.', 'error')
        return redirect(url_for('animal_detail', id=id))
    
    animal = Animal.query.get_or_404(id)
    
    if request.method == 'POST':
        old_values = {
            'status': animal.status,
            'location_id': animal.location_id
        }
        
        animal.name = request.form.get('name')
        animal.species = request.form.get('species')
        animal.breed = request.form.get('breed')
        animal.age = request.form.get('age')
        animal.sex = request.form.get('sex')
        animal.location_id = request.form.get('location_id') or None
        animal.medical_notes = request.form.get('medical_notes')
        animal.behavioral_notes = request.form.get('behavioral_notes')
        animal.special_needs = request.form.get('special_needs')
        new_status = request.form.get('status')
        
        # Check if status changed to adopted
        if new_status == 'adopted' and animal.status != 'adopted':
            animal.adopted_date = datetime.now()
            animal.adopter_name = request.form.get('adopter_name')
            animal.adopter_contact = request.form.get('adopter_contact')
        
        if new_status == 'foster':
            animal.foster_out_date = datetime.now()
            animal.foster_name = request.form.get('foster_name')
            animal.foster_contact = request.form.get('foster_contact')
        
        animal.status = new_status
        
        new_values = {
            'status': animal.status,
            'location_id': animal.location_id
        }
        
        db.session.commit()
        log_action('update_animal', 'animal', animal.id, old_values, new_values)
        
        if new_status == 'adopted' and old_values['status'] != 'adopted':
            flash('Animal marked as adopted! Adoption supplies automatically deducted from inventory.', 'success')
        else:
            flash('Animal updated successfully!', 'success')
        
        return redirect(url_for('animal_detail', id=id))
    
    locations = AnimalLocation.query.filter_by(active=True).order_by(AnimalLocation.name).all()
    return render_template('animal_edit.html', animal=animal, locations=locations)

@app.route('/logs/phone', methods=['GET', 'POST'])
@login_required
def phone_logs():
    if not current_user.has_permission('view_phone_logs'):
        flash('You do not have permission to view phone logs.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if not current_user.has_permission('edit_phone_logs'):
            flash('You do not have permission to create phone logs.', 'error')
            return redirect(url_for('phone_logs'))
        
        log = PhoneLog(
            caller_name=request.form.get('caller_name'),
            caller_phone=request.form.get('caller_phone'),
            issue=request.form.get('issue'),
            action_taken=request.form.get('action_taken'),
            follow_up_needed=request.form.get('follow_up_needed') == 'on',
            created_by=current_user.id
        )
        db.session.add(log)
        db.session.commit()
        log_action('create_phone_log', 'phone_log', log.id)
        flash('Phone log created successfully!', 'success')
        return redirect(url_for('phone_logs'))
    
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'all')
    
    query = PhoneLog.query
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    pagination = query.order_by(PhoneLog.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    
    return render_template('phone_logs.html', pagination=pagination, status_filter=status_filter)

@app.route('/logs/phone/<int:id>')
@login_required
def phone_log_detail(id):
    if not current_user.has_permission('view_phone_logs'):
        flash('You do not have permission to view phone logs.', 'error')
        return redirect(url_for('dashboard'))
    
    log = PhoneLog.query.get_or_404(id)
    return render_template('phone_log_detail.html', log=log)

@app.route('/logs/phone/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def phone_log_edit(id):
    if not current_user.has_permission('edit_phone_logs'):
        flash('You do not have permission to edit phone logs.', 'error')
        return redirect(url_for('phone_log_detail', id=id))
    
    log = PhoneLog.query.get_or_404(id)
    
    if request.method == 'POST':
        log.caller_name = request.form.get('caller_name')
        log.caller_phone = request.form.get('caller_phone')
        log.issue = request.form.get('issue')
        log.action_taken = request.form.get('action_taken')
        log.follow_up_needed = request.form.get('follow_up_needed') == 'on'
        log.status = request.form.get('status')
        
        if log.status == 'resolved':
            log.resolved_at = datetime.now()
        
        db.session.commit()
        log_action('update_phone_log', 'phone_log', log.id)
        flash('Phone log updated successfully!', 'success')
        return redirect(url_for('phone_log_detail', id=id))
    
    return render_template('phone_log_edit.html', log=log)

@app.route('/logs/donations', methods=['GET', 'POST'])
@login_required
def donations():
    if not current_user.has_permission('view_donations'):
        flash('You do not have permission to view donations.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if not current_user.has_permission('edit_donations'):
            flash('You do not have permission to create donations.', 'error')
            return redirect(url_for('donations'))
        
        donation = Donation(
            donor_name=request.form.get('donor_name'),
            donor_contact=request.form.get('donor_contact'),
            donation_type=request.form.get('donation_type'),
            amount=request.form.get('amount') or None,
            item_description=request.form.get('item_description'),
            notes=request.form.get('notes'),
            created_by=current_user.id
        )
        db.session.add(donation)
        db.session.flush()
        
        # Automatically add item donations to inventory if they match existing items
        if donation.donation_type == 'item' and donation.item_description:
            # Parse the description to try to find matching inventory items
            description = donation.item_description.lower()
            
            # Get all inventory items
            inventory_items = InventoryItem.query.all()
            
            for inv_item in inventory_items:
                # Simple matching - check if item name is in description
                if inv_item.item_name.lower() in description:
                    # Try to extract quantity (look for numbers in description)
                    import re
                    numbers = re.findall(r'\d+', description)
                    quantity = int(numbers[0]) if numbers else 1
                    
                    # Add to inventory
                    transaction = InventoryTransaction(
                        item_id=inv_item.id,
                        transaction_type='in',
                        quantity=quantity,
                        reason='donation',
                        reference_type='donation',
                        reference_id=donation.id,
                        notes=f'From {donation.donor_name or "Anonymous"}',
                        created_by=current_user.id
                    )
                    inv_item.quantity += quantity
                    db.session.add(transaction)
        
        db.session.commit()
        log_action('create_donation', 'donation', donation.id)
        flash('Donation logged successfully! Matching items automatically added to inventory.', 'success')
        return redirect(url_for('donations'))
    
    page = request.args.get('page', 1, type=int)
    donation_type = request.args.get('type', 'all')
    
    query = Donation.query
    if donation_type != 'all':
        query = query.filter_by(donation_type=donation_type)
    
    pagination = query.order_by(Donation.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    
    return render_template('donations.html', pagination=pagination, donation_type=donation_type)

@app.route('/logs/donation/<int:id>')
@login_required
def donation_detail(id):
    if not current_user.has_permission('view_donations'):
        flash('You do not have permission to view donations.', 'error')
        return redirect(url_for('dashboard'))
    
    donation = Donation.query.get_or_404(id)
    return render_template('donation_detail.html', donation=donation)

@app.route('/logs/donation/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def donation_edit(id):
    if not current_user.has_permission('edit_donations'):
        flash('You do not have permission to edit donations.', 'error')
        return redirect(url_for('donation_detail', id=id))
    
    donation = Donation.query.get_or_404(id)
    
    if request.method == 'POST':
        donation.donor_name = request.form.get('donor_name')
        donation.donor_contact = request.form.get('donor_contact')
        donation.donation_type = request.form.get('donation_type')
        donation.amount = request.form.get('amount') or None
        donation.item_description = request.form.get('item_description')
        donation.notes = request.form.get('notes')
        donation.status = request.form.get('status')
        
        db.session.commit()
        log_action('update_donation', 'donation', donation.id)
        flash('Donation updated successfully!', 'success')
        return redirect(url_for('donation_detail', id=id))
    
    return render_template('donation_edit.html', donation=donation)

@app.route('/logs/items-out', methods=['GET', 'POST'])
@login_required
def items_out():
    if not current_user.has_permission('view_items_out'):
        flash('You do not have permission to view items out.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if not current_user.has_permission('edit_items_out'):
            flash('You do not have permission to log items out.', 'error')
            return redirect(url_for('items_out'))
        
        item = ItemOut(
            item_name=request.form.get('item_name'),
            quantity=request.form.get('quantity') or None,
            reason=request.form.get('reason'),
            recipient=request.form.get('recipient'),
            animal_id=request.form.get('animal_id') or None,
            notes=request.form.get('notes'),
            created_by=current_user.id
        )
        db.session.add(item)
        db.session.flush()
        
        # Automatically deduct from inventory if item exists
        inv_item = InventoryItem.query.filter_by(item_name=item.item_name).first()
        if inv_item:
            quantity = item.quantity or 1
            if inv_item.quantity >= quantity:
                transaction = InventoryTransaction(
                    item_id=inv_item.id,
                    transaction_type='out',
                    quantity=quantity,
                    reason=item.reason,
                    reference_type='item_out',
                    reference_id=item.id,
                    notes=item.notes,
                    created_by=current_user.id
                )
                inv_item.quantity -= quantity
                db.session.add(transaction)
                flash('Item logged and automatically deducted from inventory!', 'success')
            else:
                flash(f'Item logged but insufficient inventory ({inv_item.quantity} available).', 'warning')
        else:
            flash('Item logged (not tracked in inventory).', 'success')
        
        db.session.commit()
        log_action('create_item_out', 'item_out', item.id)
        return redirect(url_for('items_out'))
    
    page = request.args.get('page', 1, type=int)
    pagination = ItemOut.query.order_by(ItemOut.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    animals = Animal.query.all()
    
    return render_template('items_out.html', pagination=pagination, animals=animals)

# ==================== INVENTORY ROUTES ====================

@app.route('/inventory')
@login_required
def inventory():
    if not current_user.has_permission('view_inventory'):
        flash('You do not have permission to view inventory.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    category_filter = request.args.get('category', 'all')
    
    query = InventoryItem.query
    if category_filter != 'all':
        query = query.filter_by(category=category_filter)
    
    items = query.order_by(InventoryItem.item_name).all()
    
    return render_template('inventory_page.html', items=items, category_filter=category_filter)

@app.route('/inventory/new', methods=['GET', 'POST'])
@login_required
def inventory_new():
    if not current_user.has_permission('edit_inventory'):
        flash('You do not have permission to add inventory items.', 'error')
        return redirect(url_for('inventory'))
    
    if request.method == 'POST':
        item = InventoryItem(
            item_name=request.form.get('item_name'),
            category=request.form.get('category'),
            quantity=request.form.get('quantity') or 0,
            unit=request.form.get('unit'),
            location=request.form.get('location'),
            reorder_point=request.form.get('reorder_point') or None,
            notes=request.form.get('notes')
        )
        db.session.add(item)
        db.session.commit()
        log_action('create_inventory_item', 'inventory_item', item.id)
        flash('Inventory item created successfully!', 'success')
        return redirect(url_for('inventory'))
    
    return redirect(url_for('inventory'))

@app.route('/inventory/<int:id>')
@login_required
def inventory_detail(id):
    if not current_user.has_permission('view_inventory'):
        flash('You do not have permission to view inventory.', 'error')
        return redirect(url_for('dashboard'))
    
    item = InventoryItem.query.get_or_404(id)
    return render_template('inventory_detail.html', item=item)

@app.route('/inventory/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def inventory_edit(id):
    if not current_user.has_permission('edit_inventory'):
        flash('You do not have permission to edit inventory.', 'error')
        return redirect(url_for('inventory_detail', id=id))
    
    item = InventoryItem.query.get_or_404(id)
    
    if request.method == 'POST':
        old_quantity = item.quantity
        
        item.item_name = request.form.get('item_name')
        item.category = request.form.get('category')
        item.quantity = int(request.form.get('quantity') or 0)
        item.unit = request.form.get('unit')
        item.location = request.form.get('location')
        item.reorder_point = request.form.get('reorder_point') or None
        item.notes = request.form.get('notes')
        
        # If quantity changed directly, create adjustment transaction
        if item.quantity != old_quantity:
            diff = item.quantity - old_quantity
            transaction = InventoryTransaction(
                item_id=item.id,
                transaction_type='in' if diff > 0 else 'out',
                quantity=abs(diff),
                reason='adjustment',
                notes='Manual quantity adjustment',
                created_by=current_user.id
            )
            db.session.add(transaction)
        
        db.session.commit()
        log_action('update_inventory_item', 'inventory_item', item.id)
        flash('Inventory item updated successfully!', 'success')
        return redirect(url_for('inventory_detail', id=id))
    
    return render_template('inventory_edit.html', item=item)

@app.route('/inventory/<int:id>/adjust', methods=['POST'])
@login_required
def inventory_adjust(id):
    if not current_user.has_permission('edit_inventory'):
        flash('You do not have permission to adjust inventory.', 'error')
        return redirect(url_for('inventory_detail', id=id))
    
    item = InventoryItem.query.get_or_404(id)
    
    quantity = int(request.form.get('quantity'))
    transaction_type = request.form.get('transaction_type')
    reason = request.form.get('reason')
    notes = request.form.get('notes')
    
    # Create transaction
    transaction = InventoryTransaction(
        item_id=item.id,
        transaction_type=transaction_type,
        quantity=quantity,
        reason=reason,
        notes=notes,
        created_by=current_user.id
    )
    
    # Update inventory quantity
    if transaction_type == 'in':
        item.quantity += quantity
    else:
        item.quantity -= quantity
        if item.quantity < 0:
            item.quantity = 0
            flash('Warning: Inventory quantity cannot go below 0. Set to 0.', 'warning')
    
    db.session.add(transaction)
    db.session.commit()
    
    log_action('adjust_inventory', 'inventory_item', item.id)
    flash(f'Inventory adjusted: {quantity} items {"added" if transaction_type == "in" else "removed"}!', 'success')
    return redirect(url_for('inventory_detail', id=id))

@app.route('/inventory/<int:id>/delete', methods=['POST'])
@login_required
def inventory_delete(id):
    if current_user.role not in ['admin', 'management']:
        flash('Only administrators and management can delete inventory items.', 'error')
        return redirect(url_for('inventory_detail', id=id))
    
    item = InventoryItem.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    log_action('delete_inventory_item', 'inventory_item', id)
    flash('Inventory item deleted successfully!', 'success')
    return redirect(url_for('inventory'))

# ==================== USER MANAGEMENT ROUTES ====================

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    if not current_user.has_permission('manage_users'):
        flash('You do not have permission to manage users.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        user = User(
            username=request.form.get('username'),
            email=request.form.get('email'),
            role=request.form.get('role'),
            active=True
        )
        user.set_password(request.form.get('password'))
        
        # Set default permissions for role
        user.set_permissions(user.get_default_permissions())
        
        db.session.add(user)
        db.session.commit()
        log_action('create_user', 'user', user.id, new_value={'username': user.username, 'role': user.role})
        flash('User created successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    users = User.query.all()
    
    # Check for permission warnings
    permission_warnings = []
    critical_permissions = ['manage_users', 'view_audit_log', 'manage_locations']
    
    for perm in critical_permissions:
        has_users = any(u.has_permission(perm) and u.active for u in users)
        if not has_users:
            permission_warnings.append(f'No active users have permission: {perm.replace("_", " ").title()}')
    
    return render_template('admin_users.html', users=users, permission_warnings=permission_warnings)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allow users to change their own password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Verify current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password'))
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('change_password'))
        
        # Basic password validation
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return redirect(url_for('change_password'))
        
        # Update password
        current_user.set_password(new_password)
        db.session.commit()
        log_action('change_password', 'user', current_user.id)
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.has_permission('manage_users'):
        flash('You do not have permission to edit users.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        old_values = {
            'username': user.username,
            'email': user.email,
            'role': user.role
        }
        
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        new_role = request.form.get('role')
        
        # If role changed, reset permissions to defaults
        if new_role != user.role:
            user.role = new_role
            user.permissions = None  # Will use get_default_permissions()
            flash(f'Role changed to {new_role}. Permissions reset to defaults.', 'warning')
        
        # Update password if provided
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password:
            if new_password != confirm_password:
                flash('Passwords do not match.', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            
            if len(new_password) < 4:
                flash('Password must be at least 4 characters.', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            
            user.set_password(new_password)
            flash('Password updated successfully.', 'success')
        
        new_values = {
            'username': user.username,
            'email': user.email,
            'role': user.role
        }
        
        db.session.commit()
        log_action('update_user', 'user', user.id, old_values, new_values)
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/admin/user/<int:user_id>/permissions', methods=['GET', 'POST'])
@login_required
def edit_user_permissions(user_id):
    if not current_user.has_permission('manage_users'):
        flash('You do not have permission to edit user permissions.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Build permissions dict from form
        permissions = {}
        all_permissions = [
            'view_dashboard', 'view_animals', 'edit_animals', 'add_animals',
            'view_checklists', 'complete_checklists', 'manage_checklists',
            'view_time_clock', 'use_time_clock', 'view_all_time_entries',
            'view_phone_logs', 'edit_phone_logs', 'view_donations', 'edit_donations',
            'view_items_out', 'edit_items_out', 'view_audit_log',
            'manage_users', 'manage_locations', 'view_maintenance', 'manage_maintenance',
            'view_staff_notes', 'add_staff_notes', 'view_inventory', 'edit_inventory'
        ]
        
        for perm in all_permissions:
            permissions[perm] = request.form.get(perm) == 'on'
        
        old_perms = user.get_permissions()
        user.set_permissions(permissions)
        db.session.commit()
        
        log_action('update_user_permissions', 'user', user.id, old_perms, permissions)
        flash('User permissions updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    permissions = user.get_permissions()
    return render_template('user_permissions_editor.html', user=user, permissions=permissions)

@app.route('/admin/user/<int:user_id>/permissions/reset', methods=['POST'])
@login_required
def reset_user_permissions(user_id):
    if not current_user.has_permission('manage_users'):
        flash('You do not have permission to reset user permissions.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    old_perms = user.get_permissions()
    
    # Reset to default for their role
    user.permissions = None  # Will use get_default_permissions()
    db.session.commit()
    
    log_action('reset_user_permissions', 'user', user.id, old_perms, user.get_default_permissions())
    flash(f'Permissions reset to defaults for {user.role} role!', 'success')
    return redirect(url_for('edit_user_permissions', user_id=user_id))

@app.route('/admin/user/<int:user_id>/toggle-status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if not current_user.has_permission('manage_users'):
        flash('You do not have permission to change user status.', 'error')
        return redirect(url_for('dashboard'))
    
    if user_id == current_user.id:
        flash('You cannot deactivate your own account!', 'error')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    user.active = not user.active
    
    db.session.commit()
    log_action('toggle_user_status', 'user', user.id, 
              {'active': not user.active}, {'active': user.active})
    
    status = 'activated' if user.active else 'deactivated'
    flash(f'User {user.username} has been {status}!', 'success')
    return redirect(url_for('admin_users'))

# ==================== LOCATION MANAGEMENT ROUTES ====================

@app.route('/admin/locations', methods=['GET', 'POST'])
@login_required
def manage_locations():
    if not current_user.has_permission('manage_locations'):
        flash('You do not have permission to manage locations.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        location = AnimalLocation(
            name=request.form.get('name'),
            location_type=request.form.get('location_type'),
            capacity=request.form.get('capacity') or None,
            notes=request.form.get('notes'),
            active=True
        )
        db.session.add(location)
        db.session.commit()
        log_action('create_location', 'animal_location', location.id, new_value={'name': location.name})
        flash('Location created successfully!', 'success')
        return redirect(url_for('manage_locations'))
    
    locations = AnimalLocation.query.order_by(AnimalLocation.name).all()
    
    # Count animals at each location
    for location in locations:
        location.animal_count = Animal.query.filter_by(location_id=location.id).count()
    
    # Get unread notes count for navigation
    unread_notes_count = 0
    if current_user.role in ['admin', 'management', 'board']:
        unread_notes_count = StaffNote.query.filter_by(is_read=False).count()
    
    return render_template('manage_locations.html', locations=locations, unread_notes_count=unread_notes_count)

@app.route('/admin/location/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_location(id):
    if not current_user.has_permission('manage_locations'):
        flash('You do not have permission to edit locations.', 'error')
        return redirect(url_for('manage_locations'))
    
    location = AnimalLocation.query.get_or_404(id)
    
    if request.method == 'POST':
        old_values = {
            'name': location.name,
            'active': location.active
        }
        
        location.name = request.form.get('name')
        location.location_type = request.form.get('location_type')
        location.capacity = request.form.get('capacity') or None
        location.notes = request.form.get('notes')
        location.active = request.form.get('active') == 'on'
        
        new_values = {
            'name': location.name,
            'active': location.active
        }
        
        db.session.commit()
        log_action('update_location', 'animal_location', location.id, old_values, new_values)
        flash('Location updated successfully!', 'success')
        return redirect(url_for('manage_locations'))
    
    animal_count = Animal.query.filter_by(location_id=location.id).count()
    return render_template('edit_location.html', location=location, animal_count=animal_count)

@app.route('/admin/location/<int:id>/toggle-status', methods=['POST'])
@login_required
def toggle_location_status(id):
    if not current_user.has_permission('manage_locations'):
        flash('You do not have permission to change location status.', 'error')
        return redirect(url_for('manage_locations'))
    
    location = AnimalLocation.query.get_or_404(id)
    
    # Check if any animals are at this location
    if not location.active:
        # Activating is always ok
        location.active = True
    else:
        # Deactivating - check for animals
        animal_count = Animal.query.filter_by(location_id=location.id).count()
        if animal_count > 0:
            flash(f'Cannot deactivate location with {animal_count} animal(s). Move animals first.', 'error')
            return redirect(url_for('manage_locations'))
        location.active = False
    
    db.session.commit()
    log_action('toggle_location_status', 'animal_location', location.id)
    
    status = 'activated' if location.active else 'deactivated'
    flash(f'Location {location.name} has been {status}!', 'success')
    return redirect(url_for('manage_locations'))

# ==================== STAFF NOTES ROUTES ====================

@app.route('/staff-notes', methods=['GET', 'POST'])
@login_required
def staff_notes():
    if not current_user.has_permission('add_staff_notes'):
        flash('You do not have permission to add staff notes.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        note = StaffNote(
            user_id=current_user.id,
            title=request.form.get('title'),
            content=request.form.get('content'),
            priority=request.form.get('priority', 'normal'),
            category=request.form.get('category', 'general')
        )
        db.session.add(note)
        db.session.commit()
        log_action('create_staff_note', 'staff_note', note.id)
        flash('Staff note created successfully! Management will be notified.', 'success')
        return redirect(url_for('dashboard'))
    
    # Get user's recent notes
    recent_notes = StaffNote.query.filter_by(user_id=current_user.id).order_by(
        StaffNote.created_at.desc()
    ).limit(5).all()
    
    return render_template('staff_notes.html', recent_notes=recent_notes)

@app.route('/staff-notes/view')
@login_required
def view_all_staff_notes():
    if not current_user.has_permission('view_staff_notes'):
        flash('You do not have permission to view all staff notes.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    filter_priority = request.args.get('priority', 'all')
    filter_read = request.args.get('read', 'all')
    
    query = StaffNote.query
    
    if filter_priority != 'all':
        query = query.filter_by(priority=filter_priority)
    
    if filter_read == 'unread':
        query = query.filter_by(is_read=False)
    elif filter_read == 'read':
        query = query.filter_by(is_read=True)
    
    pagination = query.order_by(StaffNote.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    
    return render_template('view_staff_notes.html', pagination=pagination, 
                         filter_priority=filter_priority, filter_read=filter_read)

@app.route('/staff-notes/<int:id>/mark-read', methods=['POST'])
@login_required
def mark_staff_note_read(id):
    if not current_user.has_permission('view_staff_notes'):
        flash('You do not have permission.', 'error')
        return redirect(url_for('dashboard'))
    
    note = StaffNote.query.get_or_404(id)
    note.is_read = True
    db.session.commit()
    
    return redirect(url_for('view_all_staff_notes'))

# ==================== MAINTENANCE ROUTES ====================

@app.route('/maintenance/tickets', methods=['GET', 'POST'])
@login_required
def maintenance_tickets():
    if not current_user.has_permission('view_maintenance'):
        flash('You do not have permission to view maintenance tickets.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if not current_user.has_permission('manage_maintenance'):
            flash('You do not have permission to create maintenance tickets.', 'error')
            return redirect(url_for('maintenance_tickets'))
        
        ticket = MaintenanceTicket(
            title=request.form.get('title'),
            description=request.form.get('description'),
            priority=request.form.get('priority', 'medium'),
            category=request.form.get('category'),
            location=request.form.get('location'),
            created_by=current_user.id
        )
        db.session.add(ticket)
        db.session.commit()
        log_action('create_maintenance_ticket', 'maintenance_ticket', ticket.id)
        flash('Maintenance ticket created successfully!', 'success')
        return redirect(url_for('maintenance_tickets'))
    
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', 'all')
    priority_filter = request.args.get('priority', 'all')
    
    query = MaintenanceTicket.query
    
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    if priority_filter != 'all':
        query = query.filter_by(priority=priority_filter)
    
    pagination = query.order_by(MaintenanceTicket.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    
    return render_template('maintenance_tickets.html', pagination=pagination,
                         status_filter=status_filter, priority_filter=priority_filter)

@app.route('/maintenance/ticket/<int:id>')
@login_required
def maintenance_ticket_detail(id):
    if not current_user.has_permission('view_maintenance'):
        flash('You do not have permission to view maintenance tickets.', 'error')
        return redirect(url_for('dashboard'))
    
    ticket = MaintenanceTicket.query.get_or_404(id)
    return render_template('maintenance_ticket_detail.html', ticket=ticket)

@app.route('/maintenance/ticket/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def maintenance_ticket_edit(id):
    if not current_user.has_permission('manage_maintenance'):
        flash('You do not have permission to edit maintenance tickets.', 'error')
        return redirect(url_for('maintenance_ticket_detail', id=id))
    
    ticket = MaintenanceTicket.query.get_or_404(id)
    
    if request.method == 'POST':
        old_status = ticket.status
        
        ticket.title = request.form.get('title')
        ticket.description = request.form.get('description')
        ticket.priority = request.form.get('priority')
        ticket.status = request.form.get('status')
        ticket.category = request.form.get('category')
        ticket.location = request.form.get('location')
        ticket.assigned_to = request.form.get('assigned_to') or None
        ticket.estimated_cost = request.form.get('estimated_cost') or None
        ticket.actual_cost = request.form.get('actual_cost') or None
        ticket.notes = request.form.get('notes')
        
        due_date_str = request.form.get('due_date')
        if due_date_str:
            ticket.due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
        
        if ticket.status == 'completed' and old_status != 'completed':
            ticket.completed_at = datetime.now()
        
        db.session.commit()
        log_action('update_maintenance_ticket', 'maintenance_ticket', ticket.id)
        flash('Maintenance ticket updated successfully!', 'success')
        return redirect(url_for('maintenance_ticket_detail', id=id))
    
    # Get maintenance users for assignment
    maintenance_users = User.query.filter(
        (User.role == 'maintenance') | (User.role == 'admin') | (User.role == 'management')
    ).filter_by(active=True).all()
    
    return render_template('maintenance_ticket_edit.html', ticket=ticket, 
                         maintenance_users=maintenance_users)

# ==================== ADMIN ROUTES ====================

@app.route('/admin/checklists', methods=['GET', 'POST'])
@login_required
def admin_checklists():
    if not current_user.has_permission('manage_checklists'):
        flash('You do not have permission to manage checklists.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        checklist = Checklist(
            name=request.form.get('name'),
            description=request.form.get('description'),
            time_period=request.form.get('time_period'),
            created_by=current_user.id
        )
        db.session.add(checklist)
        db.session.flush()
        
        tasks = request.form.getlist('tasks[]')
        for i, task in enumerate(tasks):
            if task.strip():
                item = ChecklistItem(checklist_id=checklist.id, task=task, order=i)
                db.session.add(item)
        
        db.session.commit()
        log_action('create_checklist', 'checklist', checklist.id)
        flash('Checklist created successfully!', 'success')
        return redirect(url_for('admin_checklists'))
    
    checklists = Checklist.query.all()
    
    for checklist in checklists:
        checklist.completion_count = ChecklistCompletion.query.filter_by(checklist_id=checklist.id).count()
    
    return render_template('admin_checklists.html', checklists=checklists)
    
@app.route('/admin/checklist/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def admin_checklist_edit(id):
    if not current_user.has_permission('manage_checklists'):
        flash('You do not have permission to edit checklists.', 'error')
        return redirect(url_for('admin_checklists'))
    
    checklist = Checklist.query.get_or_404(id)
    
    if request.method == 'POST':
        checklist.name = request.form.get('name')
        checklist.description = request.form.get('description')
        checklist.time_period = request.form.get('time_period')
        
        ChecklistItem.query.filter_by(checklist_id=id).delete()
        
        tasks = request.form.getlist('tasks[]')
        for i, task in enumerate(tasks):
            if task.strip():
                item = ChecklistItem(checklist_id=checklist.id, task=task, order=i)
                db.session.add(item)
        
        db.session.commit()
        log_action('update_checklist', 'checklist', checklist.id)
        flash('Checklist updated successfully!', 'success')
        return redirect(url_for('admin_checklists'))
    
    return render_template('admin_checklist_edit.html', checklist=checklist)

@app.route('/admin/checklist/<int:id>/delete', methods=['POST'])
@login_required
def admin_checklist_delete(id):
    if not current_user.has_permission('manage_checklists'):
        flash('You do not have permission to delete checklists.', 'error')
        return redirect(url_for('admin_checklists'))
    
    checklist = Checklist.query.get_or_404(id)
    db.session.delete(checklist)
    db.session.commit()
    log_action('delete_checklist', 'checklist', id)
    flash('Checklist deleted successfully!', 'success')
    return redirect(url_for('admin_checklists'))

@app.route('/admin/animals', methods=['GET', 'POST'])
@login_required
def admin_animals():
    if not current_user.has_permission('add_animals'):
        flash('You do not have permission to add animals.', 'error')
        return redirect(url_for('animals'))
    
    if request.method == 'POST':
        animal = Animal(
            name=request.form.get('name'),
            species=request.form.get('species'),
            breed=request.form.get('breed'),
            age=request.form.get('age'),
            sex=request.form.get('sex'),
            intake_reason=request.form.get('intake_reason'),
            location_id=request.form.get('location_id') or None,
            medical_notes=request.form.get('medical_notes'),
            behavioral_notes=request.form.get('behavioral_notes'),
            special_needs=request.form.get('special_needs')
        )
        db.session.add(animal)
        db.session.commit()
        log_action('create_animal', 'animal', animal.id)
        flash('Animal added successfully!', 'success')
        return redirect(url_for('animals'))
    
    locations = AnimalLocation.query.filter_by(active=True).order_by(AnimalLocation.name).all()
    
    # Count animals at each location
    for location in locations:
        location.animal_count = Animal.query.filter_by(location_id=location.id).count()
    
    return render_template('admin_animals.html', locations=locations)

@app.route('/admin/audit')
@login_required
def audit_log():
    if not current_user.has_permission('view_audit_log'):
        flash('You do not have permission to view the audit log.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    return render_template('audit.html', pagination=pagination)

@app.route('/admin/system-settings')
@login_required
def system_settings():
    if current_user.role != 'admin':
        flash('Administrator access required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Placeholder for future system settings page
    flash('System settings page coming soon!', 'warning')
    return redirect(url_for('dashboard'))

@app.route('/reports/dashboard')
@login_required
def reports_dashboard():
    if current_user.role not in ['admin', 'management', 'board']:
        flash('Access restricted to management and board members.', 'error')
        return redirect(url_for('dashboard'))
    
    # Placeholder for reports
    flash('Reports and analytics coming soon!', 'warning')
    return redirect(url_for('dashboard'))

@app.context_processor
def inject_unread_notes():
    """Make unread notes count available to all templates"""
    if current_user.is_authenticated and current_user.role in ['admin', 'management', 'board']:
        unread_notes_count = StaffNote.query.filter_by(is_read=False).count()
        return dict(unread_notes_count=unread_notes_count)
    return dict(unread_notes_count=0)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Check if admin exists
        if User.query.count() == 0:
            admin_password = os.environ.get('ADMIN_PASSWORD', 'ChangeMe123!')
            admin = User(username='admin', email='admin@humanesociety.org', role='admin', active=True)
            admin.set_password(admin_password)
            admin.set_permissions(admin.get_default_permissions())
            db.session.add(admin)
            db.session.commit()
            print('⚠️  Default admin created. Username: admin')
            print('⚠️  CHANGE THE PASSWORD IMMEDIATELY!')
        
        # Add default locations if none exist
        if AnimalLocation.query.count() == 0:
            default_locations = [
                ('Isolation', 'isolation'),
                ('Lobby', 'lobby'),
                ('Cat Room 1', 'cat_room'),
                ('Cat Room 2', 'cat_room'),
                ('Cat Room 3', 'cat_room'),
                ('Cat Room 4', 'cat_room'),
                ('Cat Room 5', 'cat_room'),
                ('Cat Room 6', 'cat_room'),
                ('Cat Room 7', 'cat_room'),
                ('Kennels', 'kennel')
            ]
            
            for loc_name, loc_type in default_locations:
                location = AnimalLocation(name=loc_name, location_type=loc_type, active=True)
                db.session.add(location)
            
            db.session.commit()
            print('✓ Default animal locations created')
        
        # Add default inventory items if none exist
        if InventoryItem.query.count() == 0:
            default_inventory = [
                ('Collar', 'cat', 10, 'units', 'Storage Room A', 5),
                ('Collar', 'dog', 15, 'units', 'Storage Room A', 5),
                ('Leash', 'dog', 12, 'units', 'Storage Room A', 5),
                ('Cat Food', 'food', 20, 'bags', 'Food Storage', 10),
                ('Dog Food', 'food', 25, 'bags', 'Food Storage', 10),
                ('Cat Litter', 'cat', 30, 'bags', 'Storage Room B', 15),
                ('Food Sample', 'food', 50, 'bags', 'Front Desk', 20),
                ('Cleaning Spray', 'cleaning', 10, 'bottles', 'Janitorial Closet', 5),
                ('Paper Towels', 'cleaning', 20, 'rolls', 'Janitorial Closet', 10),
                ('Vaccine Supplies', 'medical', 15, 'kits', 'Medical Cabinet', 5),
            ]
            
            for name, cat, qty, unit, loc, reorder in default_inventory:
                item = InventoryItem(
                    item_name=name,
                    category=cat,
                    quantity=qty,
                    unit=unit,
                    location=loc,
                    reorder_point=reorder
                )
                db.session.add(item)
            
            db.session.commit()
            print('✓ Default inventory items created')
    
    app.run(host='0.0.0.0', port=5000, debug=False)
