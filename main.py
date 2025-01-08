import threading
import customtkinter as ctk
from tkinter import messagebox
import requests
import time

# Flask API URL
API_URL = "https://bosbes.eu.pythonanywhere.com"

def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()

class LoadingScreen(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.geometry("300x100")
        self.title("Loading")
        self.label = ctk.CTkLabel(self, text="Loading... Please wait.")
        self.label.pack(pady=20, padx=20)
        self.update_idletasks()

def show_loading_screen(parent):
    loading_screen = LoadingScreen(parent)
    parent.loading_screen = loading_screen
    parent.loading_screen.update()

def hide_loading_screen(parent):
    if hasattr(parent, 'loading_screen'):
        parent.loading_screen.destroy()
        del parent.loading_screen

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.geometry("600x450")
        self.title("ToDo App")
        self.current_user = None

        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)

        self.show_login_screen()

    def show_login_screen(self):
        clear_frame(self.container)
        self.check_connection_async()

        frame = ctk.CTkFrame(self.container, fg_color="#f4f4f9")
        frame.pack(pady=20, padx=20, fill="both", expand=True)

        header = ctk.CTkFrame(frame, fg_color="#4c6ef5", height=50, corner_radius=0)  # No rounded corners for header
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(
            header, text="Login", font=("Helvetica", 18, "bold"), text_color="white", corner_radius=0
        ).pack(side="left", padx=20)


        content_frame = ctk.CTkFrame(frame, fg_color="white", corner_radius=10)
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)

        username_entry = ctk.CTkEntry(
            content_frame,
            placeholder_text="Username",
            fg_color="white",
            text_color="black",
            corner_radius=10,
            height=40
        )
        username_entry.pack(fill="x", pady=10)

        password_entry = ctk.CTkEntry(
            content_frame,
            placeholder_text="Password",
            show="*",
            fg_color="white",
            text_color="black",
            corner_radius=10,
            height=40
        )
        password_entry.pack(fill="x", pady=10)

        def login():
            show_loading_screen(self)
            username = username_entry.get()
            password = password_entry.get()
            response = requests.post(
                f"{API_URL}/login", json={"username": username, "password": password}
            )
            hide_loading_screen(self)
            if response.status_code == 200:
                self.current_user = response.json()["user_id"]
                self.show_main_screen()
            else:
                messagebox.showerror(
                    "Login Failed", response.json().get("error", "Error")
                )

        ctk.CTkButton(
            content_frame,
            text="Login",
            command=login,
            fg_color="#4c6ef5",
            text_color="white",
            corner_radius=10,
            hover_color="#3b56cc",
            height=40
        ).pack(pady=10)

        def show_signup():
            self.show_signup_screen()

        ctk.CTkButton(
            content_frame,
            text="Signup",
            command=show_signup,
            fg_color="#f1f1f1",
            text_color="black",
            corner_radius=10,
            height=40
        ).pack(pady=5)

    def show_no_connection_screen(self):
        clear_frame(self.container)

        frame = ctk.CTkFrame(self.container, fg_color="#f4f4f9", corner_radius=10)
        frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(
            frame,
            text="No internet connection. Please check your network.",
            font=("Helvetica", 14, "bold"),
            text_color="red",
        ).pack(pady=20)

        ctk.CTkButton(
            frame,
            text="Retry",
            command=self.show_login_screen,
            fg_color="#4c6ef5",
            text_color="white",
            corner_radius=10,
            height=40
        ).pack(pady=10)

    def check_connection(self):
        try:
            show_loading_screen(self)
            requests.get(API_URL)
            hide_loading_screen(self)
        except requests.exceptions.RequestException:
            self.show_no_connection_screen()

    def check_connection_async(self):
        def run_check():
            self.check_connection()

        thread = threading.Thread(target=run_check)
        thread.start()

    def show_signup_screen(self):
        clear_frame(self.container)

        frame = ctk.CTkFrame(self.container, fg_color="#f4f4f9", corner_radius=10)
        frame.pack(pady=20, padx=20, fill="both", expand=True)

        header = ctk.CTkFrame(frame, fg_color="#4c6ef5", height=50, corner_radius=0)  # No rounded corners for header
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(
            header, text="Signup", font=("Helvetica", 18, "bold"), text_color="white", corner_radius=0
        ).pack(side="left", padx=20)


        content_frame = ctk.CTkFrame(frame, fg_color="white", corner_radius=10)
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)

        username_entry = ctk.CTkEntry(
            content_frame,
            placeholder_text="Username",
            fg_color="white",
            text_color="black",
            corner_radius=10,
            height=40
        )
        username_entry.pack(fill="x", pady=10)

        password_entry = ctk.CTkEntry(
            content_frame,
            placeholder_text="Password",
            show="*",
            fg_color="white",
            text_color="black",
            corner_radius=10,
            height=40
        )
        password_entry.pack(fill="x", pady=10)

        def signup():
            show_loading_screen(self)
            username = username_entry.get()
            password = password_entry.get()
            response = requests.post(
                f"{API_URL}/signup", json={"username": username, "password": password}
            )
            hide_loading_screen(self)
            if response.status_code == 201:
                messagebox.showinfo("Success", "Signup successful! Please login.")
                self.show_login_screen()
            else:
                messagebox.showerror(
                    "Error", response.json().get("error", "Username already exists")
                )

        ctk.CTkButton(
            content_frame,
            text="Signup",
            command=signup,
            fg_color="#4caf50",
            text_color="white",
            corner_radius=10,
            height=40
        ).pack(pady=10)

        def show_login():
            self.show_login_screen()

        ctk.CTkButton(
            content_frame,
            text="Back to Login",
            command=show_login,
            fg_color="#f1f1f1",
            text_color="black",
            corner_radius=10,
            height=40
        ).pack(pady=5)

    # Add this new method
    def show_account_screen(self):
        clear_frame(self.container)

        # Main frame setup
        frame = ctk.CTkFrame(self.container, fg_color="#f4f4f9", corner_radius=10)
        frame.pack(pady=20, padx=20, fill="both", expand=True)

        # Header
        header = ctk.CTkFrame(frame, fg_color="#4c6ef5", height=50, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkButton(
            header,
            text="Back",
            command=self.show_main_screen,
            fg_color="#4c6ef5",
            text_color="white",
            corner_radius=10,
            height=40,
        ).pack(side="left", padx=10, pady=5)

        ctk.CTkLabel(
            header,
            text="Account Settings",
            font=("Helvetica", 18, "bold"),
            text_color="white",
        ).pack(side="left", padx=20)

        # Content container
        content_frame = ctk.CTkFrame(frame, fg_color="white", corner_radius=10)
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Section for updating username
        username_section = ctk.CTkFrame(content_frame, fg_color="#f4f4f9", corner_radius=10)
        username_section.pack(fill="x", pady=10, padx=20)

        ctk.CTkLabel(
            username_section,
            text="Update Username",
            font=("Helvetica", 14, "bold"),
        ).pack(pady=10)

        username_entry = ctk.CTkEntry(
            username_section,
            placeholder_text="New Username",
            fg_color="#f9f9f9",
            text_color="black",
            corner_radius=10,
        )
        username_entry.pack(fill="x", pady=10, padx=20)

        def update_username():
            new_username = username_entry.get()
            show_loading_screen(self)
            response = requests.put(
                f"{API_URL}/update-username",
                json={"user_id": self.current_user, "new_username": new_username},
            )
            hide_loading_screen(self)
            if response.status_code == 200:
                messagebox.showinfo("Success", "Username updated successfully!")
            else:
                messagebox.showerror("Error", response.json().get("error", "Error"))

        ctk.CTkButton(
            username_section,
            text="Update Username",
            command=update_username,
            fg_color="#4caf50",
            text_color="white",
            corner_radius=10,
            height=40,
        ).pack(pady=10)

        # Section for updating password
        password_section = ctk.CTkFrame(content_frame, fg_color="#f4f4f9", corner_radius=10)
        password_section.pack(fill="x", pady=10, padx=20)

        ctk.CTkLabel(
            password_section,
            text="Update Password",
            font=("Helvetica", 14, "bold"),
        ).pack(pady=10)

        current_password_entry = ctk.CTkEntry(
            password_section,
            placeholder_text="Current Password",
            show="*",
            fg_color="#f9f9f9",
            text_color="black",
            corner_radius=10,
        )
        current_password_entry.pack(fill="x", pady=10, padx=20)

        new_password_entry = ctk.CTkEntry(
            password_section,
            placeholder_text="New Password",
            show="*",
            fg_color="#f9f9f9",
            text_color="black",
            corner_radius=10,
        )
        new_password_entry.pack(fill="x", pady=10, padx=20)

        def update_password():
            current_password = current_password_entry.get()
            new_password = new_password_entry.get()
            show_loading_screen(self)
            response = requests.put(
                f"{API_URL}/update-password",
                json={
                    "user_id": self.current_user,
                    "current_password": current_password,
                    "new_password": new_password,
                },
            )
            hide_loading_screen(self)
            if response.status_code == 200:
                messagebox.showinfo("Success", "Password updated successfully!")
            else:
                messagebox.showerror("Error", response.json().get("error", "Error"))

        ctk.CTkButton(
            password_section,
            text="Update Password",
            command=update_password,
            fg_color="#4caf50",
            text_color="white",
            corner_radius=10,
            height=40,
        ).pack(pady=10)

        # Section for deleting account
        delete_section = ctk.CTkFrame(content_frame, fg_color="#f4f4f9", corner_radius=10)
        delete_section.pack(fill="x", pady=20, padx=20)

        ctk.CTkLabel(
            delete_section,
            text="Delete Account",
            font=("Helvetica", 14, "bold"),
            text_color="red",
        ).pack(pady=10)

        delete_password_entry = ctk.CTkEntry(
            delete_section,
            placeholder_text="Enter Password to Confirm",
            show="*",
            fg_color="#f9f9f9",
            text_color="black",
            corner_radius=10,
        )
        delete_password_entry.pack(fill="x", pady=10, padx=20)

        def delete_account():
            password = delete_password_entry.get()
            if not messagebox.askyesno(
                "Confirm Deletion", 
                "Are you sure you want to delete your account? This action cannot be undone."
            ):
                return

            show_loading_screen(self)
            response = requests.delete(
                f"{API_URL}/delete-account",
                json={"user_id": self.current_user, "password": password},
            )
            hide_loading_screen(self)
            if response.status_code == 200:
                messagebox.showinfo("Success", "Account deleted successfully!")
                self.current_user = None
                self.show_login_screen()  # Redirect to login screen after account deletion
            else:
                messagebox.showerror("Error", response.json().get("error", "Error"))

        ctk.CTkButton(
            delete_section,
            text="Delete Account",
            command=delete_account,
            fg_color="#f44336",  # Red button
            text_color="white",
            hover_color="#d32f2f",  # Darker red on hover
            corner_radius=10,
            height=40,
        ).pack(pady=10)


    def show_main_screen(self):
        clear_frame(self.container)

        frame = ctk.CTkFrame(self.container, fg_color="#f4f4f9", corner_radius=0)
        frame.pack(pady=20, padx=20, fill="both", expand=True)

        action_bar = ctk.CTkFrame(frame, fg_color="#4c6ef5", height=50, corner_radius=0)
        action_bar.pack(fill="x")
        action_bar.pack_propagate(False)

        # Add "Account" button
        ctk.CTkButton(
            action_bar,
            text="Account",
            command=self.show_account_screen,
            fg_color="#ff9800",
            text_color="white",
            corner_radius=10,
            hover_color="#e68900",
            height=40,
        ).pack(side="right", padx=10, pady=5)

        ctk.CTkButton(
            action_bar,
            text="Add Note",
            command=self.show_add_edit_screen,
            fg_color="#4caf50",
            text_color="white",
            corner_radius=10,
            hover_color="#45a049",
            height=40
        ).pack(side="right", padx=10, pady=5)

        notes_frame_container = ctk.CTkFrame(frame, fg_color="white", corner_radius=10)
        notes_frame_container.pack(fill="both", expand=True)

        canvas = ctk.CTkCanvas(notes_frame_container, bg="white")
        canvas.pack(side="left", fill="both", expand=True)

        notes_frame = ctk.CTkFrame(canvas, fg_color="white")
        canvas.create_window((0, 0), window=notes_frame, anchor="nw")

        # Add a scrollbar for vertical scrolling when needed
        scrollbar = ctk.CTkScrollbar(notes_frame_container, orientation="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Add a temporary loading message
        loading_label = ctk.CTkLabel(
            notes_frame,
            text="Loading notes...",
            font=("Helvetica", 16, "bold"),
            text_color="gray",
        )
        loading_label.pack(pady=20)

        # Fetch the notes
        show_loading_screen(self)
        response = requests.get(f"{API_URL}/notes", params={"user_id": self.current_user})
        hide_loading_screen(self)

        # Remove the loading message
        loading_label.pack_forget()

        todos = response.json() if response.status_code == 200 else []

        row, col = 0, 0
        if todos:
            for todo in todos:
                note_id = todo["id"]
                note_text = todo["note"]

                # Check if the note is empty
                display_text = note_text[:100] if note_text.strip() else "Empty Note"
                text_color = "black" if note_text.strip() else "gray"  # Lighter color for empty notes

                ctk.CTkButton(
                    notes_frame,
                    text=display_text,
                    fg_color="#ffeb3b",  # Yellow color for notes
                    text_color=text_color,
                    hover_color="#fdd835",  # Darker yellow for hover effect
                    corner_radius=10,
                    anchor="nw",
                    height=150,
                    command=lambda id=note_id: self.show_add_edit_screen(todo_id=id),
                ).grid(row=row, column=col, padx=10, pady=10, sticky="nsew")

                col += 1
                if col > 2:
                    col = 0
                    row += 1

            notes_frame.update_idletasks()
            canvas.config(scrollregion=canvas.bbox("all"))
        else:
            ctk.CTkLabel(
                notes_frame,
                text="No notes found. Click on 'Add Note' to add a new note.",
                font=("Helvetica", 14, "bold"),
                text_color="gray",
            ).pack(pady=20, padx=20)


    def show_add_edit_screen(self, todo_id=None):
        clear_frame(self.container)

        frame = ctk.CTkFrame(self.container, fg_color="#f4f4f9", corner_radius=10)
        frame.pack(pady=20, padx=20, fill="both", expand=True)

        header = ctk.CTkFrame(frame, fg_color="#4c6ef5", height=50, corner_radius=0)  # No rounded corners for header
        header.pack(fill="x")
        header.pack_propagate(False)

        # Back button positioned at left with background color
        ctk.CTkButton(
            header,
            text="Back",
            command=self.show_main_screen,
            fg_color="#4c6ef5",
            text_color="white",
            corner_radius=10,
            height=40
        ).pack(side="left", padx=10, pady=5)

        ctk.CTkLabel(
            header,
            text="Edit Note" if todo_id else "Add Note",
            font=("Helvetica", 18, "bold"),
            text_color="white",
        ).pack(side="right", padx=20)  # Positioned at the right

        content_frame = ctk.CTkFrame(frame, fg_color="white", corner_radius=10)
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)

        note_entry = ctk.CTkEntry(
            content_frame,
            placeholder_text="Write your note here...",
            height=200,
            fg_color="#f9f9f9",
            text_color="black",
            corner_radius=10,
        )
        note_entry.pack(fill="x", pady=10)

        if todo_id:
            show_loading_screen(self)
            response = requests.get(f"{API_URL}/notes", params={"user_id": self.current_user})
            hide_loading_screen(self)
            notes = response.json()
            for note in notes:
                if note["id"] == todo_id:
                    note_entry.insert(0, note["note"])

        button_bar = ctk.CTkFrame(content_frame, fg_color="white", corner_radius=10)
        button_bar.pack(fill="x", pady=20)

        def save_note():
            show_loading_screen(self)
            note = note_entry.get()
            if todo_id:
                response = requests.put(f"{API_URL}/notes/{todo_id}", json={"note": note})
            else:
                response = requests.post(
                    f"{API_URL}/notes", json={"user_id": self.current_user, "note": note}
                )
            hide_loading_screen(self)
            if response.status_code in [200, 201]:
                self.show_main_screen()
            else:
                messagebox.showerror("Error", response.json().get("error", "Error"))

        ctk.CTkButton(
            button_bar,
            text="Save",
            command=save_note,
            fg_color="#4caf50",
            text_color="white",
            corner_radius=10,
            width=100,
            height=40
        ).pack(side="left", padx=10)

        if todo_id:
            def delete_note():
                show_loading_screen(self)
                response = requests.delete(f"{API_URL}/notes/{todo_id}")
                hide_loading_screen(self)
                if response.status_code == 200:
                    self.show_main_screen()
                else:
                    messagebox.showerror("Error", response.json().get("error", "Error"))

            ctk.CTkButton(
                button_bar,
                text="Delete",
                command=delete_note,
                fg_color="#e74c3c",
                text_color="white",
                corner_radius=10,
                width=100,
                height=40
            ).pack(side="left", padx=10)

if __name__ == "__main__":
    app = App()
    app.mainloop()
