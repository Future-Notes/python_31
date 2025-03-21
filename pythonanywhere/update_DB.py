from sqlalchemy import inspect,text
def update_tables():
	from app import app,db as B
	with app.app_context():
		D=inspect(B.engine);F=set(D.get_table_names())
		for A in B.metadata.sorted_tables:
			if A.name not in F:print(f"Creating missing table: {A.name}");A.create(B.engine)
		for A in B.metadata.sorted_tables:
			G={A['name']for A in D.get_columns(A.name)}
			for C in A.columns:
				if C.name not in G:
					print(f"Adding missing column '{C.name}' to table '{A.name}'");H=text(f"ALTER TABLE {A.name} ADD COLUMN {C.name} {C.type}")
					with B.engine.connect()as E:E.execute(H);E.commit()
		print('Database schema update complete.')