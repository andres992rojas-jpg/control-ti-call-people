-- CONTROL TI · MIGRACIÓN DE USUARIOS Y NOMBRES DE ACCESO
-- Ejecutar UNA sola vez en Supabase > SQL Editor > New query > Run.
-- No elimina cuentas, contraseñas, registros ni auditoría.

begin;

alter table public.control_ti_profiles
  add column if not exists username text;

update public.control_ti_profiles
set
  username = case lower(email)
    when 'controlti-admin@example.com' then 'ADMIN'
    when 'controlti-andres@example.com' then 'ANDRES'
    when 'controlti-juan@example.com' then 'JUAN'
    else coalesce(
      nullif(upper(regexp_replace(split_part(coalesce(email, ''), '@', 1), '[^a-zA-Z0-9_.-]', '', 'g')), ''),
      'USER_' || upper(substr(id::text, 1, 8))
    )
  end,
  full_name = case lower(email)
    when 'controlti-admin@example.com' then 'Administrador'
    when 'controlti-andres@example.com' then 'Andrés Rojas'
    when 'controlti-juan@example.com' then 'Juan Diego'
    else full_name
  end
where username is null or btrim(username) = '';

alter table public.control_ti_profiles
  alter column username set not null;

create unique index if not exists control_ti_profiles_username_lower_uidx
  on public.control_ti_profiles (lower(username));

create or replace function public.control_ti_lookup_login_email(p_username text)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select p.email
  from public.control_ti_profiles p
  where lower(p.username) = lower(btrim(coalesce(p_username, '')))
    and p.active = true
  limit 1;
$$;

revoke all on function public.control_ti_lookup_login_email(text) from public;
grant execute on function public.control_ti_lookup_login_email(text) to anon, authenticated;

create or replace function public.control_ti_admin_update_user(
  p_user_id uuid,
  p_new_username text,
  p_full_name text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_username text := upper(btrim(coalesce(p_new_username, '')));
  v_full_name text := btrim(coalesce(p_full_name, ''));
begin
  if auth.uid() is null then
    raise exception 'Debes iniciar sesión.' using errcode = '42501';
  end if;

  if not exists (
    select 1 from public.control_ti_profiles p
    where p.id = auth.uid() and p.role = 'admin' and p.active = true
  ) then
    raise exception 'Solo ADMIN puede modificar los usuarios.' using errcode = '42501';
  end if;

  if v_username !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{2,23}$' then
    raise exception 'El usuario debe tener entre 3 y 24 caracteres: letras, números, punto, guion o guion bajo.';
  end if;

  if length(v_full_name) < 2 or length(v_full_name) > 80 then
    raise exception 'El nombre visible debe tener entre 2 y 80 caracteres.';
  end if;

  if not exists (
    select 1 from public.control_ti_profiles p where p.id = p_user_id and p.active = true
  ) then
    raise exception 'No se encontró un usuario activo.';
  end if;

  update public.control_ti_profiles
  set username = v_username, full_name = v_full_name
  where id = p_user_id;

  return jsonb_build_object('success', true, 'username', v_username, 'full_name', v_full_name);
end;
$$;

revoke all on function public.control_ti_admin_update_user(uuid, text, text) from public, anon;
grant execute on function public.control_ti_admin_update_user(uuid, text, text) to authenticated;

commit;

-- Verificación:
-- select full_name, username, role, active
-- from public.control_ti_profiles order by role, username;
