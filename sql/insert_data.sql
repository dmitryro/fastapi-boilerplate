INSERT INTO roles (id, name, permissions)
VALUES
  (1, 'admin',  ARRAY['create','read','update','delete','superuser']),
  (2, 'guest',  ARRAY['read'])
ON CONFLICT DO NOTHING;
