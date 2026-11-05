import { createClient } from "https://esm.sh/@supabase/supabase-js@2.57.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, x-client-info, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

function getSecretKey(): string | null {
  const legacy = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (legacy) return legacy;

  const raw = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw);
    return typeof parsed.default === "string" ? parsed.default : null;
  } catch {
    return null;
  }
}

function jsonResponse(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders,
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return jsonResponse(405, { error: "Método no permitido." });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const secretKey = getSecretKey();

    if (!supabaseUrl || !secretKey) {
      console.error("Faltan las variables de entorno requeridas.");
      return jsonResponse(500, { error: "La función no está configurada correctamente." });
    }

    const authHeader = req.headers.get("Authorization") || "";
    const accessToken = authHeader.replace(/^Bearer\s+/i, "").trim();

    if (!accessToken) {
      return jsonResponse(401, { error: "Debes iniciar sesión para realizar esta acción." });
    }

    const adminClient = createClient(supabaseUrl, secretKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    // Verifica el token contra Supabase Auth; no confía en datos enviados por el navegador.
    const { data: callerData, error: callerError } = await adminClient.auth.getUser(accessToken);
    if (callerError || !callerData.user) {
      return jsonResponse(401, { error: "La sesión no es válida o ha expirado." });
    }

    // Confirma en la base de datos que quien llama sea ADMIN y esté activo.
    const { data: callerProfile, error: profileError } = await adminClient
      .from("control_ti_profiles")
      .select("role, active")
      .eq("id", callerData.user.id)
      .maybeSingle();

    if (profileError) {
      console.error("Error consultando el perfil del solicitante:", profileError.message);
      return jsonResponse(500, { error: "No se pudo verificar el perfil administrador." });
    }

    if (!callerProfile || callerProfile.role !== "admin" || callerProfile.active !== true) {
      return jsonResponse(403, { error: "Solo ADMIN puede cambiar contraseñas de otras cuentas." });
    }

    const body = await req.json().catch(() => ({}));
    const userId = typeof body.userId === "string" ? body.userId.trim() : "";
    const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";

    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(userId)) {
      return jsonResponse(400, { error: "Selecciona una cuenta válida." });
    }

    if (newPassword.length < 8 || newPassword.length > 128) {
      return jsonResponse(400, { error: "La contraseña debe tener entre 8 y 128 caracteres." });
    }

    const { data: targetProfile, error: targetError } = await adminClient
      .from("control_ti_profiles")
      .select("id, full_name, active")
      .eq("id", userId)
      .maybeSingle();

    if (targetError || !targetProfile) {
      return jsonResponse(404, { error: "No se encontró la cuenta seleccionada." });
    }

    if (targetProfile.active !== true) {
      return jsonResponse(400, { error: "La cuenta seleccionada está inactiva." });
    }

    const { error: updateError } = await adminClient.auth.admin.updateUserById(userId, {
      password: newPassword,
    });

    if (updateError) {
      console.error("Error actualizando contraseña:", updateError.message);
      return jsonResponse(400, { error: "Supabase no pudo actualizar la contraseña." });
    }

    // Nunca registra ni devuelve la contraseña.
    return jsonResponse(200, {
      success: true,
      message: "Contraseña actualizada correctamente.",
      userId,
      fullName: targetProfile.full_name,
    });
  } catch (error) {
    console.error("Error inesperado en admin-set-password:", error);
    return jsonResponse(500, { error: "Ocurrió un error inesperado al actualizar la contraseña." });
  }
});
