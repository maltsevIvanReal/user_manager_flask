from logging import DEBUG
from flask import render_template, request, redirect
from flask_login import login_user, logout_user, current_user, login_required
from frontend.forms import *
from models.models import *
from config import *


def isAdminUser(current_user):
    admin = Role.query.filter_by(name="administrator").first()
    for obj in current_user._roles:
        if obj == admin:
            return True


def isAdminGroup(current_user):
    admin_role = Role.query.filter_by(name="administrator").first()
    for group in current_user._groups:
        for role in group._roles:
            if role == admin_role:
                return True


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


@app.route('/logout')
def logout():
    current_user.authenticated = False
    db.session.add(current_user)
    db.session.commit()
    logout_user()
    return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    form.Login.choices = [(s.id, s.name) for s in db.session.query(User).all()]
    return render_template("login.html", form=form)


@app.route("/login_me", methods=["GET", "POST"])
def login_me():
    user_id = request.form.get("Login")
    user = User.query.filter_by(id=user_id).first()
    if user:
        user.authenticated = True
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect("/")
    return render_template("index.html", login=login, user=user)


@app.route("/")
@login_required
def index():
    if isAdminUser(current_user) or isAdminGroup(current_user):
        administrator = db.session.query(Role).filter_by(name="administrator").first()
        print("TUTA")
        return render_template("index.html", administrator=administrator)
    elif current_user.is_authenticated:
        administrator = db.session.query(Role).filter_by(name="administrator").first()
        return render_template("index.html", administrator=administrator)
    else:
        return redirect("/login")


@app.route("/users")
@login_required
def users():
    administrator = db.session.query(Role).filter_by(name="administrator").first()
    data_users = db.session.query(User).all()
    data_roles = db.session.query(Role).all()
    data_groups = db.session.query(Group).all()

    formAdd = MyFormAdd()
    if formAdd.validate_on_submit():
        return redirect('/add_user')

    formDeleteUser = MyFormDelete()
    if formDeleteUser.validate_on_submit():
        return redirect('/delete_user')

    formUpdate = MyFormUpdate()
    if formUpdate.validate_on_submit():
        return redirect('/update_user')

    formDeleteUserRole = MyFormDelete()
    if formDeleteUserRole.validate_on_submit():
        return redirect("/delete_user_role")

    formSelectUserRole = MyFormSelectRoleUser()
    formSelectUserRole.role_id.choices = [(s.id, s.name) for s in db.session.query(Role).all()]
    if formSelectUserRole.validate_on_submit():
        return redirect("/update_user_role")

    formDeleteUserGroup = MyFormDelete()
    if formDeleteUserGroup.validate():
        return redirect("/delete_user_group")

    formSelectUserGroup = MyFormSelectGroupUser()
    formSelectUserGroup.id.choices = [(s.id, s.name) for s in db.session.query(Group).all()]
    if formSelectUserGroup.validate_on_submit():
        return redirect("/update_user_group")

    return render_template("users.html",
                           data=data_users,
                           data_roles=data_roles,
                           data_groups=data_groups,
                           form_add=formAdd,
                           form_del=formDeleteUser,
                           form_updt=formUpdate,
                           form_select_user_role=formSelectUserRole,
                           form_delete_user_role=formDeleteUserRole,
                           form_select_user_group=formSelectUserGroup,
                           form_delete_user_group=formDeleteUserGroup,
                           administrator=administrator)


@app.route("/groups")
@login_required
def group():
    data_users = db.session.query(User).all()
    data_groups = db.session.query(Group).all()

    formAddGroup = MyFormAdd()
    if formAddGroup.validate_on_submit():
        return redirect('/add_group')

    formDeleteGroup = MyFormDelete()
    if formDeleteGroup.validate_on_submit():
        return redirect('/delete_group')

    formUpdateGroup = MyFormUpdate()
    if formUpdateGroup.validate_on_submit():
        return redirect('/update_group')

    formSelectGroupUser = MyFormSelectGroupUser()
    formSelectGroupUser.id.choices = [(s.id, s.name) for s in db.session.query(User).all()]
    if formSelectGroupUser.validate_on_submit():
        return redirect("/update_group_user")

    formDeleteGroupUser = MyFormDelete()
    if formDeleteGroupUser.validate_on_submit():
        return redirect("/delete_group_user")

    return render_template("groups.html",
                           data=data_groups,
                           data_users=data_users,
                           form_add_group=formAddGroup,
                           form_delete_group=formDeleteGroup,
                           form_updt=formUpdateGroup,
                           form_select_group_user=formSelectGroupUser,
                           forom_delete_group_user=formDeleteGroupUser
                           )


@app.route("/roles")
@login_required
def roles():
    data_roles = db.session.query(Role).all()
    data_users = db.session.query(User).all()
    data_groups = db.session.query(Group).all()

    formAddRole = MyFormAdd()
    if formAddRole.validate_on_submit():
        return redirect('/add_role')

    formUpdateRole = MyFormUpdate()
    if formUpdateRole.validate_on_submit():
        return redirect('/update_role')

    formDeleteRole = MyFormDelete()
    if formDeleteRole.validate_on_submit():
        return redirect('/delete_role')

    formDeleteRoleUser = MyFormDelete()
    if formDeleteRoleUser.validate_on_submit():
        return redirect("/delete_role_user")

    formSelectRoleUser = MyFormSelectRoleUser()
    formSelectRoleUser.role_id.choices = [(s.id, s.name) for s in db.session.query(User).all()]
    if formSelectRoleUser.validate_on_submit():
        return redirect("/update_role_user")

    formDeleteGroupRole = MyFormDelete()
    if formDeleteGroupRole.validate():
        return redirect("/delete_group_role")

    formSelectGroupRole = MyFormSelectGroupRole()
    formSelectGroupRole.group_id.choices = [(s.id, s.name) for s in db.session.query(Group).all()]
    if formSelectGroupRole.validate_on_submit():
        return redirect("/update_role_group")

    return render_template("roles.html",
                           data=data_roles,
                           data_users=data_users,
                           data_groups=data_groups,
                           form_add_role=formAddRole,
                           form_update_role=formUpdateRole,
                           form_delete_role=formDeleteRole,
                           form_delete_role_user=formDeleteRoleUser,
                           from_select_role_user=formSelectRoleUser,
                           form_delete_group_role=formDeleteGroupRole,
                           form_select_group_role=formSelectGroupRole)


@app.route("/add_user", methods=["GET", "POST"])
@login_required
def user_add():
    try:
        user = User(name=request.form.get("name"))
        name = user.name
        db.session.add(user)
        db.session.commit()
        role_employee_obj = Role.query.filter_by(name="employee").first()  # id = 11 : object Role with name employee
        added_user = User.query.filter_by(name=name).first()
        added_user._roles.append(role_employee_obj)
        db.session.commit()
    except Exception as e:
        print("Failed to add group")
        print(e)
    return redirect("/users")


@app.route("/update_user", methods=["POST"])
@login_required
def update():
    newname = request.form.get("newname")
    oldname = request.form.get("oldname")
    user = User.query.filter_by(name=oldname).first()
    user.name = newname
    db.session.commit()
    return redirect("/users")


@app.route("/delete_user", methods=["POST"])
@login_required
def delete():
    user_id = request.form.get("user_id")
    user = User.query.filter_by(id=user_id).first()
    user._groups.clear()
    user._roles.clear()
    db.session.add(user)
    db.session.commit()
    db.session.delete(user)
    db.session.commit()
    return redirect("/users")


@app.route("/delete_user_role", methods=["POST"])
@login_required
def delete_user_role():
    role_id = request.form.get("id")
    user_id = request.form.get("user_id")
    main_user_id = db.session.query(User).get(user_id)
    main_role_id = db.session.query(Role).get(role_id)

    if main_role_id.name == "employee":
        admin_object = Role.query.filter_by(name="administrator").first()
        for obj in main_role_id.users:
            if obj == main_user_id:
                main_role_id.users.remove(main_user_id)
                db.session.commit()
                main_user_id._roles.append(admin_object)
                db.session.commit()

    elif main_role_id.name == "administrator":
        employee_object = Role.query.filter_by(name="employee").first()
        for obj in main_role_id.users:
            if obj == main_user_id:
                main_role_id.users.remove(main_user_id)
                db.session.commit()
                main_user_id._roles.append(employee_object)
                db.session.commit()

    else:
        main_user_id._roles.remove(main_role_id)
        db.session.commit()

    return redirect("/users")


@app.route("/update_user_role", methods=["POST"])
@login_required
def update_user_role():
    role_id = request.form.get("role_id")
    user_id = request.form.get("user_id")
    if role_id is None:
        return redirect("/users")
    else:
        main_user_id = db.session.query(User).get(user_id)
        main_role_id = db.session.query(Role).get(role_id)

        if main_role_id.name == "administrator":
            employee_object = Role.query.filter_by(name="employee").first()
            for obj in main_user_id._roles:
                if obj == employee_object:
                    main_user_id._roles.remove(employee_object)
                    db.session.commit()
                    main_user_id._roles.append(main_role_id)
                    db.session.commit()

        elif main_role_id.name == "employee":
            admin_object = Role.query.filter_by(name="administrator").first()
            for obj in main_user_id._roles:
                if obj == admin_object:
                    main_user_id._roles.remove(admin_object)
                    db.session.commit()
                    main_user_id._roles.append(main_role_id)
                    db.session.commit()
        else:
            main_user_id._roles.append(main_role_id)
            db.session.commit()

        return redirect("/users")


@app.route("/update_user_group", methods=["POST"])
@login_required
def update_user_group():
    group_id = request.form.get("id")
    user_id = request.form.get("user_id")
    if group_id is None:
        return redirect("/users")
    else:
        main_user_id = db.session.query(User).get(user_id)
        main_group_id = db.session.query(Group).get(group_id)
        main_user_id._groups.append(main_group_id)
        db.session.commit()
        return redirect("/users")


@app.route("/delete_user_group", methods=["POST"])
@login_required
def delete_user_group():
    group_id = request.form.get("id")
    user_id = request.form.get("user_id")
    main_user_id = db.session.query(User).get(user_id)
    main_group_id = db.session.query(Group).get(group_id)
    main_user_id._groups.remove(main_group_id)
    db.session.commit()

    return redirect("/users")


@app.route("/add_group", methods=["GET", "POST"])
@login_required
def group_add():
    if request.form:
        try:
            group = Group(name=request.form.get("name"))
            db.session.add(group)
            db.session.commit()
        except Exception as e:
            print("Failed to add group")
            print(e)

    return redirect("/groups")


@app.route("/update_group", methods=["POST"])
@login_required
def update_group():
    newname = request.form.get("newname")
    oldname = request.form.get("oldname")
    group = Group.query.filter_by(name=oldname).first()
    group.name = newname
    db.session.commit()
    return redirect("/groups")


@app.route("/delete_group", methods=["POST"])
@login_required
def delete_group():
    group_id = request.form.get("group_id")
    group = Group.query.filter_by(id=group_id).first()
    group.users.clear()
    group._roles.clear()
    db.session.commit()
    db.session.delete(group)
    db.session.commit()

    return redirect("/groups")


@app.route("/update_group_user", methods=["POST"])
@login_required
def update_group_user():
    group_id = request.form.get("id")
    user_id = request.form.get("user_id")
    if group_id is None:
        return redirect("/groups")
    else:
        main_group_id = db.session.query(Group).get(user_id)
        main_user_id = db.session.query(User).get(group_id)
        main_user_id._groups.append(main_group_id)
        db.session.commit()

        return redirect("/groups")


@app.route("/delete_group_user", methods=["POST"])
@login_required
def delete_group_user():
    group_id = request.form.get("id")
    user_id = request.form.get("user_id")
    main_user_id = db.session.query(User).get(user_id)
    main_group_id = db.session.query(Group).get(group_id)
    main_group_id.users.remove(main_user_id)
    db.session.commit()

    return redirect("/groups")


@app.route("/add_role", methods=["GET", "POST"])
@login_required
def role_add():
    if request.form:
        try:
            role = Role(name=request.form.get("name"))
            db.session.add(role)
            db.session.commit()
        except Exception as e:
            print("Failed to add role")


    return redirect("/roles")


@app.route("/update_role", methods=["POST"])
@login_required
def update_role():
    newname = request.form.get("newname")
    oldname = request.form.get("oldname")

    role = Role.query.filter_by(name=oldname).first()
    if role.name.lower() == "employee" or role.name.lower() == "administrator":
        return redirect("/roles")
    else:
        role.name = newname
        db.session.commit()
        return redirect("/roles")


@app.route("/delete_role", methods=["POST"])
@login_required
def delete_role():
    role_id = request.form.get("id")
    role = Role.query.filter_by(id=role_id).first()
    role.groups.clear()
    role.users.clear()
    db.session.commit()
    db.session.delete(role)
    db.session.commit()
    return redirect("/roles")


@app.route("/delete_role_user", methods=["POST"])
@login_required
def delete_role_user():
    role_id = request.form.get("id")
    user_id = request.form.get("user_id")
    main_user_id = db.session.query(User).get(user_id)
    main_role_id = db.session.query(Role).get(role_id)
    main_role_id.users.remove(main_user_id)
    db.session.commit()
    return redirect("/roles")


@app.route("/update_role_user", methods=["POST"])
@login_required
def update_role_user():
    role_id = request.form.get("user_id")
    user_id = request.form.get("role_id")
    main_user_id = db.session.query(User).get(user_id)
    main_role_id = db.session.query(Role).get(role_id)
    if main_role_id.name == "employee":
        admin_object = Role.query.filter_by(name="administrator").first()
        for obj in main_role_id.users:
            if obj == main_user_id:
                main_role_id.users.remove(main_user_id)
                db.session.commit()
                main_user_id._roles.append(admin_object)
                db.session.commit()
    elif main_role_id.name == "administrator":
        employee_object = Role.query.filter_by(name="employee").first()
        for obj in main_role_id.users:
            if obj == main_user_id:
                main_role_id.users.remove(main_user_id)
                db.session.commit()
                main_user_id._roles.append(employee_object)
                db.session.commit()
    else:
        main_user_id._roles.append(main_role_id)
        db.session.commit()

    return redirect("/roles")


@app.route("/delete_group_role", methods=["POST"])
@login_required
def delete_group_role():
    role_id = request.form.get("id")
    group_id = request.form.get("group_id")
    main_role_id = db.session.query(Role).get(role_id)
    main_group_id = db.session.query(Group).get(group_id)
    main_role_id.groups.remove(main_group_id)
    db.session.commit()
    return redirect("/roles")


@app.route("/update_role_group", methods=["POST"])
@login_required
def update_role_group():
    role_id = request.form.get("role_id")
    group_id = request.form.get("group_id")
    if role_id is None:
        return redirect("/users")
    else:
        main_group_id = db.session.query(Group).get(group_id)
        main_role_id = db.session.query(Role).get(role_id)
        main_role_id.groups.append(main_group_id)
        db.session.commit()
        return redirect("/roles")


if __name__ == "__main__":
    app.run(debug=DEBUG)
