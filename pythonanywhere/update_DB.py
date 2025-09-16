from sqlalchemy import inspect, text
from flask_sqlalchemy import SQLAlchemy

def update_tables():
    from app import app
    from app import db

    with app.app_context():
        inspector = inspect(db.engine)

        # Step 1: Ensure all tables exist first
        existing_tables = set(inspector.get_table_names())
        for table in db.metadata.sorted_tables:
            if table.name not in existing_tables:
                print(f"Creating missing table: {table.name}")
                table.create(db.engine)

        # Step 2: Add missing columns with default values
        for table in db.metadata.sorted_tables:
            existing_columns = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name not in existing_columns:
                    default_clause = ""
                    if column.default is not None:
                        # Handle simple SQLAlchemy ColumnDefaults
                        if callable(column.default.arg):
                            # skip server-side callables (like func.now()), handle separately if needed
                            pass
                        else:
                            default_val = column.default.arg
                            if isinstance(default_val, str):
                                default_val = f"'{default_val}'"
                            default_clause = f" DEFAULT {default_val}"

                    # Handle non-nullable columns without defaults (must give something)
                    if not column.nullable and default_clause == "":
                        # provide a generic default depending on type
                        if hasattr(column.type, "python_type"):
                            py_type = column.type.python_type
                            if py_type in [int, float]:
                                default_clause = " DEFAULT 0"
                            elif py_type == bool:
                                default_clause = " DEFAULT 0"
                            else:
                                default_clause = " DEFAULT ''"

                    alter_stmt = text(f'ALTER TABLE {table.name} ADD COLUMN {column.name} {column.type}{default_clause}')
                    print(f"Executing: {alter_stmt}")
                    with db.engine.connect() as conn:
                        conn.execute(alter_stmt)
                        conn.commit()

        print("Database schema update complete.")

if __name__ == "__main__":
    update_tables()