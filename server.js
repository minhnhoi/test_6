// server.js

require("dotenv").config();
const express = require("express");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const cors = require("cors");
const streamifier = require("streamifier");
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");

const app = express();
const port = process.env.PORT || 3000;

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

app.use(cors());
app.use(express.json({ limit: "50mb" }));

// =======================
// MongoDB Access Logging (Trace-friendly)
// =======================

app.set("trust proxy", true); // để lấy IP thật khi chạy sau proxy/nginx

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  return (
    (typeof xff === "string" && xff.split(",")[0].trim()) ||
    req.ip ||
    req.socket?.remoteAddress ||
    ""
  );
}

function getForwardedForRaw(req) {
  const xff = req.headers["x-forwarded-for"];
  return typeof xff === "string" ? xff : "";
}

// Gom theo "IP mạng"
// - IPv4: gom /24 => 192.168.1.23 -> 192.168.1.*
// - IPv6: gom /64 (thô) => lấy 4 segment đầu -> xxxx:xxxx:xxxx:xxxx::/64
function getNetworkKeyFromIp(ip) {
  if (!ip) return "unknown";

  // xử lý IPv6 mapped IPv4: ::ffff:192.168.1.23
  const v4 = ip.includes("::ffff:") ? ip.split("::ffff:")[1] : ip;

  // Nếu là IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v4)) {
    const parts = v4.split(".");
    return `${parts[0]}.${parts[1]}.${parts[2]}.*`;
  }

  // Nếu là IPv6
  const seg = ip.split(":").filter(Boolean);
  return `${seg.slice(0, 4).join(":")}::/64`;
}

function makeRequestId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

async function connectMongo() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.warn("⚠️ MONGODB_URI chưa cấu hình -> bỏ qua Mongo logging.");
    return;
  }
  try {
    await mongoose.connect(uri, {
      autoIndex: true,
      serverSelectionTimeoutMS: 8000,
    });
    console.log("✅ MongoDB connected");
  } catch (e) {
    console.error("❌ MongoDB connect error:", e.message);
  }
}

/**
 * LEGACY (giữ lại để tham khảo / tương thích)
 * Trước đây log mỗi request 1 record (create).
 * Giờ dùng NetworkAgg (gộp theo IP mạng + lưu rolling events) ở dưới.
 */
const AccessLogSchema = new mongoose.Schema(
  {
    ts: { type: Date, default: Date.now, index: true },
    ip: { type: String, index: true },
    method: String,
    path: String,
    status: Number,
    durationMs: Number,
    userAgent: String,
    referer: String,
    acceptLanguage: String,
    client: {
      timezone: String,
      platform: String,
      language: String,
      screen: { w: Number, h: Number },
      deviceMemory: Number,
      hardwareConcurrency: Number,
      touch: Boolean,
      deviceName: String,
    },
  },
  { versionKey: false }
);
const AccessLog =
  mongoose.models.AccessLog || mongoose.model("AccessLog", AccessLogSchema);

/**
 * NEW: Network Aggregate (gộp theo IP mạng) + phục vụ truy vết
 */
const NetworkAggSchema = new mongoose.Schema(
  {
    // gộp theo mạng để thống kê
    networkKey: { type: String, index: true },

    // IP đầy đủ gần nhất + XFF raw (đối chiếu proxy)
    lastIp: { type: String, index: true },
    lastXff: String,

    firstSeen: { type: Date, default: Date.now, index: true },
    lastSeen: { type: Date, default: Date.now, index: true },
    hits: { type: Number, default: 0 },

    // thống kê theo path
    paths: { type: Map, of: Number, default: {} },

    // UA unique (để nhìn tổng quan)
    userAgents: { type: [String], default: [] },

    // event gần nhất
    lastEvent: {
      ts: Date,
      requestId: String,
      ip: String,
      xff: String,
      method: String,
      path: String,
      status: Number,
      durationMs: Number,
      ua: String,
      referer: String,
      acceptLanguage: String,
    },

    // rolling events gần nhất (giữ N event)
    events: {
      type: [
        {
          ts: Date,
          requestId: String,
          ip: String,
          xff: String,
          method: String,
          path: String,
          status: Number,
          durationMs: Number,
          ua: String,
          referer: String,
          acceptLanguage: String,
        },
      ],
      default: [],
    },

    // optional client info (cái mới nhất từ /telemetry/client)
    client: {
      timezone: String,
      platform: String,
      language: String,
      screen: { w: Number, h: Number },
      deviceMemory: Number,
      hardwareConcurrency: Number,
      touch: Boolean,
      deviceName: String,
    },
  },
  { versionKey: false }
);

// TTL tự xóa sau 30 ngày (bạn có thể bỏ nếu muốn giữ lâu)
NetworkAggSchema.index({ lastSeen: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 30 });

const NetworkAgg =
  mongoose.models.NetworkAgg || mongoose.model("NetworkAgg", NetworkAggSchema);
// =======================
// Upload Lifetime Counter (Global, Mongo)
// =======================
const UploadCounterSchema = new mongoose.Schema(
  {
    key: { type: String, unique: true, index: true },
    value: { type: Number, default: 0 },
  },
  { versionKey: false }
);

const UploadCounter =
  mongoose.models.UploadCounter ||
  mongoose.model("UploadCounter", UploadCounterSchema);


// =======================
// FaceID Storage (MongoDB)
// =======================
const FaceIdSchema = new mongoose.Schema(
  {
    label: { type: String, required: true, unique: true, index: true },
    descriptors: { type: [[Number]], required: true }, // array of 128-d vectors
    updatedAt: { type: Date, default: Date.now },
  },
  { versionKey: false }
);

const FaceId =
  mongoose.models.FaceId || mongoose.model("FaceId", FaceIdSchema);


async function incUploadCounter(delta = 1) {
  if (mongoose.connection?.readyState !== 1) return null; // Mongo chưa sẵn sàng
  const doc = await UploadCounter.findOneAndUpdate(
    { key: "lifetime_upload_count" },
    { $inc: { value: delta } },
    { upsert: true, new: true }
  );
  return doc?.value ?? 0;
}

async function getUploadCounter() {
  if (mongoose.connection?.readyState !== 1) return 0;
  const doc = await UploadCounter.findOne({ key: "lifetime_upload_count" }).lean();
  return doc?.value ?? 0;
}

// Log mọi request (audit nhẹ). Không log body/query/auth/cookie.
app.use((req, res, next) => {
  const start = Date.now();
  const requestId = makeRequestId();

  // trả requestId cho client để debug/support
  res.setHeader("x-request-id", requestId);

  res.on("finish", async () => {
    try {
      if (mongoose.connection?.readyState !== 1) return;

      const ip = getClientIp(req);
      const xffRaw = getForwardedForRaw(req);
      const networkKey = getNetworkKeyFromIp(ip);

      const durationMs = Date.now() - start;
      const reqPath = req.originalUrl || req.url;

      const ua = req.headers["user-agent"] || "";
      const referer = req.headers["referer"] || "";
      const acceptLanguage = req.headers["accept-language"] || "";
      const now = new Date();

      const event = {
        ts: now,
        requestId,
        ip,
        xff: xffRaw,
        method: req.method,
        path: reqPath,
        status: res.statusCode,
        durationMs,
        ua,
        referer,
        acceptLanguage,
      };

      await NetworkAgg.updateOne(
        { networkKey },
        {
          $setOnInsert: { firstSeen: now, networkKey },
          $set: {
            lastSeen: now,
            lastIp: ip,
            lastXff: xffRaw,
            lastEvent: event,
          },
          $inc: {
            hits: 1,
            [`paths.${reqPath}`]: 1,
          },
          ...(ua ? { $addToSet: { userAgents: ua } } : {}),
          $push: {
            events: {
              $each: [event],
              $slice: -50, // giữ 50 event gần nhất
            },
          },
        },
        { upsert: true }
      );
    } catch (e) {
      console.warn("network agg log error:", e.message);
    }
  });

  next();
});

// Client gửi thêm thông tin thiết bị (optional)
app.post("/telemetry/client", async (req, res) => {
  try {
    if (mongoose.connection?.readyState !== 1) {
      return res.json({ success: false, message: "Mongo chưa sẵn sàng" });
    }

    const body = req.body || {};
    const ip = getClientIp(req);
    const xffRaw = getForwardedForRaw(req);
    const networkKey = getNetworkKeyFromIp(ip);
    const now = new Date();

    await NetworkAgg.updateOne(
      { networkKey },
      {
        $setOnInsert: { firstSeen: now, networkKey },
        $set: {
          lastSeen: now,
          lastIp: ip,
          lastXff: xffRaw,
          client: {
            timezone: body.timezone,
            platform: body.platform,
            language: body.language,
            screen: body.screen,
            deviceMemory: body.deviceMemory,
            hardwareConcurrency: body.hardwareConcurrency,
            touch: body.touch,
            deviceName: body.deviceName,
          },
        },
      },
      { upsert: true }
    );

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "123456";
const MAX_FILES_LIMIT = 50;

const FACE_DB_PATH = path.join(__dirname, "face_db.json");
const FACE_DB_CLOUD_ID = "system_face_id_backup.json";

const accounts = [
  {
    name: "Kho Chính (Cloudinary main)",
    cloud_name: process.env.CLOUD_NAME_1,
    api_key: process.env.CLOUD_API_KEY_1,
    api_secret: process.env.CLOUD_API_SECRET_1,
  },
  {
    name: "Kho Dự Phòng 1 (Cloudinary 1)",
    cloud_name: process.env.CLOUD_NAME_2,
    api_key: process.env.CLOUD_API_KEY_2,
    api_secret: process.env.CLOUD_API_SECRET_2,
  },
  {
    name: "Kho Dự Phòng 2 (Cloudinary 2)",
    cloud_name: process.env.CLOUD_NAME_3,
    api_key: process.env.CLOUD_API_KEY_3,
    api_secret: process.env.CLOUD_API_SECRET_3,
  },
  {
    name: "Kho Dự Phòng 3 (Cloudinary 3)",
    cloud_name: process.env.CLOUD_NAME_4,
    api_key: process.env.CLOUD_API_KEY_4,
    api_secret: process.env.CLOUD_API_SECRET_4,
  },
];

const setCloudinaryConfig = (index) => {
  const acc = accounts[index];

  if (!acc || !acc.cloud_name || !acc.api_key || !acc.api_secret) {
    return null;
  }

  try {
    cloudinary.config({
      cloud_name: acc.cloud_name,
      api_key: acc.api_key,
      api_secret: acc.api_secret,
    });
    return acc;
  } catch (e) {
    console.error("Lỗi config Cloudinary:", e);
    return null;
  }
};

async function backupFaceDBToCloud() {
  console.log(">> [SYSTEM] Đang backup Face ID lên Cloudinary.");

  setCloudinaryConfig(0);

  if (!fs.existsSync(FACE_DB_PATH)) return;

  try {
    await cloudinary.uploader.upload(FACE_DB_PATH, {
      public_id: FACE_DB_CLOUD_ID,
      resource_type: "raw",
      overwrite: true,
      folder: "system_backup",
      invalidate: true,
    });
    console.log(">> [SYSTEM] Backup Face ID thành công!");
  } catch (error) {
    console.error(">> [SYSTEM] Lỗi backup Face ID:", error.message);
  }
}

async function restoreFaceDBFromCloud() {
  console.log(">> [SYSTEM] 🚀 Đang khôi phục Face ID từ Cloudinary...");
  setCloudinaryConfig(0);

  try {
    const url = cloudinary.url("system_backup/" + FACE_DB_CLOUD_ID, {
      resource_type: "raw",
    });

    const fetchUrl = `${url}?t=${new Date().getTime()}`;
    const response = await fetch(fetchUrl, { cache: "no-store" });

    if (!response.ok) throw new Error("File backup chưa tồn tại hoặc lỗi mạng");

    const data = await response.json();

    fs.writeFileSync(FACE_DB_PATH, JSON.stringify(data, null, 2));
    console.log(">> [SYSTEM] 👌 Khôi phục dữ liệu Face ID thành công!");
  } catch (error) {
    console.log(
      ">> [SYSTEM] ⚠️ Chưa có bản backup hoặc lỗi (" +
      error.message +
      "). ❌ Tạo Database rỗng."
    );

    if (!fs.existsSync(FACE_DB_PATH)) {
      fs.writeFileSync(FACE_DB_PATH, "[]");
    }
  }
}

app.get("/face-id/load", async (req, res) => {
  try {
    // Ưu tiên MongoDB (đúng yêu cầu mới)
    if (mongoose.connection?.readyState === 1) {
      const doc = await FaceId.findOne({ label: "Admin" }).lean();
      if (!doc) return res.json({ success: true, data: [] });
      return res.json({
        success: true,
        data: [{ label: doc.label, descriptors: doc.descriptors }],
      });
    }

    // Fallback legacy (nếu Mongo chưa sẵn sàng)
    if (!fs.existsSync(FACE_DB_PATH)) return res.json({ success: true, data: [] });
    const raw = fs.readFileSync(FACE_DB_PATH);
    const data = JSON.parse(raw);
    return res.json({ success: true, data });
  } catch (e) {
    console.error("FaceID load error:", e);
    return res.json({ success: true, data: [] });
  }
});

app.post("/face-id/register", async (req, res) => {
  try {
    const { label, descriptors } = req.body || {};
    if (!label || !Array.isArray(descriptors) || descriptors.length === 0) {
      return res.status(400).json({ success: false, message: "INVALID_PAYLOAD" });
    }

    // Validate nhẹ: mỗi descriptor phải là array số (face-api thường 128)
    for (const d of descriptors) {
      if (!Array.isArray(d) || d.length < 64) {
        return res.status(400).json({ success: false, message: "INVALID_DESCRIPTOR" });
      }
    }

    // Ưu tiên MongoDB
    if (mongoose.connection?.readyState === 1) {
      await FaceId.updateOne(
        { label },
        { $set: { descriptors, updatedAt: new Date() } },
        { upsert: true }
      );
      return res.json({ success: true, message: "Đã lưu FaceID vào MongoDB" });
    }

    // Fallback legacy: file json (nếu Mongo chưa sẵn sàng)
    let users = [];
    if (fs.existsSync(FACE_DB_PATH)) {
      try {
        users = JSON.parse(fs.readFileSync(FACE_DB_PATH));
      } catch (_) { }
    }
    users = users.filter((u) => u.label !== "Admin");
    users.push({ label, descriptors });
    fs.writeFileSync(FACE_DB_PATH, JSON.stringify(users, null, 2));
    backupFaceDBToCloud();
    return res.json({ success: true, message: "Mongo chưa sẵn sàng, đã lưu tạm vào file." });
  } catch (e) {
    console.error("FaceID register error:", e);
    return res.status(500).json({ success: false, message: "Lỗi Server lưu Face ID" });
  }
});

app.delete("/face-id/clear", async (req, res) => {
  try {
    // Ưu tiên MongoDB
    if (mongoose.connection?.readyState === 1) {
      await FaceId.deleteOne({ label: "Admin" });
      return res.json({ success: true, message: "Đã xóa FaceID trong MongoDB" });
    }

    // Fallback legacy
    fs.writeFileSync(FACE_DB_PATH, "[]");
    backupFaceDBToCloud();
    return res.json({ success: true, message: "Mongo chưa sẵn sàng, đã xóa file FaceID." });
  } catch (e) {
    return res.status(500).json({ success: false, message: "Lỗi khi xóa dữ liệu" });
  }
});

app.get("/stats", async (req, res) => {
  const index = req.query.index || 0;
  const acc = setCloudinaryConfig(index);

  if (!acc) {
    return res.json({
      success: true,
      isEmpty: true,
      totalFiles: 0,
      storage: { used: 0, total: 0, percent: 0 },
    });
  }

  try {
    let totalFiles = 0;

    try {
      const checkResult = await cloudinary.search
        .expression("resource_type:image OR resource_type:video OR resource_type:raw")
        .max_results(1)
        .execute();
      totalFiles = checkResult.total_count;
    } catch (err) {
      console.log(`Cổng ${index} sai mật khẩu hoặc lỗi mạng:`, err.message);
      return res.json({
        success: true,
        isAuthError: true,
        totalFiles: 0,
        storage: { used: 0, total: 0, percent: 0 },
      });
    }

    let usageData = { used: 0, total: 25, percent: 0 };
    try {
      const usageResult = await cloudinary.api.usage();
      const usedCredits = usageResult.credits?.usage || 0;
      const limitCredits = usageResult.plan_limits?.credits || 25;
      usageData = {
        used: usedCredits.toFixed(2),
        total: limitCredits,
        percent: Math.min(100, Math.round((usedCredits / limitCredits) * 100)),
      };
    } catch (e) { }

    res.json({
      success: true,
      totalFiles: totalFiles,
      storage: usageData,
      files: {
        remaining: Math.max(0, MAX_FILES_LIMIT - totalFiles),
        limit: MAX_FILES_LIMIT,
      },
    });
  } catch (error) {
    res.json({ success: false, message: "Lỗi server nội bộ" });
  }
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });


// Public metrics: Global lifetime uploads counter
app.get("/metrics/uploads", async (req, res) => {
  try {
    const count = await getUploadCounter();
    res.json({ success: true, count });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get("/accounts", (req, res) => {
  const list = accounts
    .map((acc, index) => (acc.cloud_name ? { index, name: acc.name } : null))
    .filter((item) => item !== null);
  res.json({ success: true, accounts: list });
});

app.post("/upload", upload.single("myFile"), async (req, res) => {
  if (!req.file)
    return res.status(400).json({ success: false, message: "Chưa chọn file!" });

  const index = req.body.accountIndex || 0;
  const acc = setCloudinaryConfig(index);
  if (!acc)
    return res.status(500).json({ success: false, message: "Lỗi cấu hình server." });

  const uploadStream = cloudinary.uploader.upload_stream(
    {
      folder: "upload_master",
      resource_type: "auto",
    },
    (error, result) => {
      if (error)
        return res.status(500).json({ success: false, message: error.message });
      res.json({
        success: true,
        data: {
          public_id: result.public_id,
          asset_id: result.asset_id,
          cloud_name: acc.cloud_name,
          filename: result.original_filename,
          secure_url: result.secure_url,
          resource_type: result.resource_type,
          format: result.format,
          bytes: result.bytes,
          created_at: result.created_at,
        },
      });

      // ✅ tăng tổng lượt upload (Mongo)
      incUploadCounter(1).catch(() => { });
    }
  );
  streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
});

app.post("/upload-url", async (req, res) => {
  const { url, accountIndex } = req.body;
  if (!url) return res.json({ success: false, message: "Thiếu URL" });

  const acc = setCloudinaryConfig(accountIndex || 0);
  if (!acc) return res.json({ success: false, message: "Lỗi cấu hình Cloud" });

  try {
    const result = await cloudinary.uploader.upload(url, {
      folder: "upload_master_url",
      resource_type: "auto",
    });

    res.json({
      success: true,
      data: {
        public_id: result.public_id,
        asset_id: result.asset_id,
        cloud_name: acc.cloud_name,
        filename: result.original_filename || "url_upload",
        secure_url: result.secure_url,
        resource_type: result.resource_type,
        format: result.format,
        bytes: result.bytes,
        created_at: result.created_at,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Lỗi: " + error.message });
  }
});

async function getFilesHandler(req, res, indexParam) {
  const index = indexParam || req.query.index || 0;
  const acc = setCloudinaryConfig(index);

  if (!acc) {
    return res.json({
      success: true,
      files: [],
      message: "Cổng này chưa được kết nối hoặc cấu hình sai.",
    });
  }

  try {
    const result = await cloudinary.search
      .expression("resource_type:image OR resource_type:video OR resource_type:raw")
      .sort_by("created_at", "desc")
      .max_results(500)
      .execute();

    res.json({ success: true, files: result.resources });
  } catch (e) {
    console.error(`Lỗi lấy danh sách file (Cổng ${index}):`, e.message);
    res.json({ success: false, message: e.message, files: [] });
  }
}

app.get("/files", (req, res) => getFilesHandler(req, res));

app.get("/admin/files/:index", (req, res) => {
  const token = req.headers["x-admin-pass"];
  if (token !== ADMIN_PASSWORD)
    return res.json({ success: false, message: "Sai mật khẩu Admin" });

  return getFilesHandler(req, res, req.params.index);
});

app.post("/admin/login", (req, res) => {
  const { password } = req.body;
  res.json({ success: password === ADMIN_PASSWORD });
});

app.delete("/admin/files/:index/:id", async (req, res) => {
  const token = req.headers["x-admin-pass"];
  if (token !== ADMIN_PASSWORD)
    return res.status(403).json({ success: false, message: "Forbidden" });

  const { index, id } = req.params;
  setCloudinaryConfig(index);

  try {
    const publicId = decodeURIComponent(id);
    let result = await cloudinary.uploader.destroy(publicId);

    if (result.result !== "ok") {
      result = await cloudinary.uploader.destroy(publicId, { resource_type: "video" });
    }
    if (result.result !== "ok") {
      result = await cloudinary.uploader.destroy(publicId, { resource_type: "raw" });
    }

    if (result.result === "ok" || result.result === "not found") {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: result.result });
    }
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post("/admin/rename", async (req, res) => {
  const token = req.headers["x-admin-pass"];
  if (token !== ADMIN_PASSWORD)
    return res.status(403).json({ success: false, message: "Forbidden" });

  const { accountIndex, fileId, newName } = req.body;
  setCloudinaryConfig(accountIndex);

  try {
    const result = await cloudinary.uploader.rename(fileId, newName);
    res.json({ success: true, data: result });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post("/admin/delete-batch", async (req, res) => {
  const token = req.headers["x-admin-pass"];
  if (token !== ADMIN_PASSWORD)
    return res.json({ success: false, message: "Forbidden" });

  const { accountIndex, files } = req.body;
  setCloudinaryConfig(accountIndex);

  if (!files || !Array.isArray(files) || files.length === 0) {
    return res.json({ success: false, message: "Chưa chọn file nào." });
  }

  try {
    let deletedCount = 0;
    const deletePromises = files.map(async (file) => {
      try {
        const type = file.type || "image";
        await cloudinary.uploader.destroy(file.id, { resource_type: type });
        deletedCount++;
      } catch (err) {
        console.error(`Lỗi xóa file ${file.id}:`, err.message);
      }
    });

    await Promise.all(deletePromises);
    res.json({ success: true, count: deletedCount });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.get("/admin/stats-all", async (req, res) => {
  const token = req.headers["x-admin-pass"];
  if (token !== ADMIN_PASSWORD)
    return res.json({ success: false, message: "Forbidden" });

  try {
    const results = [];

    for (let i = 0; i < accounts.length; i++) {
      const acc = accounts[i];

      if (!acc.cloud_name) {
        results.push({
          index: i,
          name: acc.name || `Server ${i + 1}`,
          percent: 0,
          usedGB: 0,
          totalGB: 0,
          status: "empty",
        });
        continue;
      }

      try {
        cloudinary.config({
          cloud_name: acc.cloud_name,
          api_key: acc.api_key,
          api_secret: acc.api_secret,
        });

        const checkCount = await cloudinary.search
          .expression("resource_type:image OR resource_type:video OR resource_type:raw")
          .max_results(1)
          .execute();

        const realTotalFiles = checkCount.total_count;
        const usageResult = await cloudinary.api.usage();
        let rawUsed = usageResult.credits?.usage || 0;
        const total = usageResult.plan_limits?.credits || 25;

        if (realTotalFiles === 0) rawUsed = 0;

        let used = Math.max(0, rawUsed);
        let finalPercent = parseFloat(((used / total) * 100).toFixed(2));

        results.push({
          index: i,
          name: acc.name,
          usedGB: used.toFixed(2),
          totalGB: total,
          percent: finalPercent,
          status: "online",
        });
      } catch (err) {
        console.error(`Lỗi check stats server ${i}:`, err.message);
        results.push({
          index: i,
          name: acc.name,
          percent: 0,
          usedGB: 0,
          totalGB: 0,
          status: "error",
          message: "Lỗi kết nối",
        });
      }
    }

    res.json({ success: true, servers: results });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post("/admin/empty-trash/:index", (req, res) => {
  res.json({ success: true, message: "Cloudinary tự động quản lý thùng rác." });
});


// =======================
// Admin: MongoDB Browser + ChatGPT Proxy
// =======================
function requireAdmin(req, res) {
  const token = req.headers["x-admin-pass"];
  if (token !== ADMIN_PASSWORD) {
    res.status(403).json({ success: false, message: "Forbidden" });
    return false;
  }
  return true;
}

app.get("/admin/mongo/collections", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  if (mongoose.connection?.readyState !== 1) {
    return res.json({ success: false, message: "Mongo chưa sẵn sàng" });
  }

  try {
    const cols = await mongoose.connection.db.listCollections().toArray();
    res.json({
      success: true,
      collections: cols.map((c) => c.name).sort(),
    });

    // ✅ tăng tổng lượt upload (Mongo)
    incUploadCounter(1).catch(() => { });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get("/admin/mongo/:collection", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  if (mongoose.connection?.readyState !== 1) {
    return res.json({ success: false, message: "Mongo chưa sẵn sàng" });
  }

  const { collection } = req.params;
  const limit = Math.min(parseInt(req.query.limit || "50", 10), 200);
  const skip = Math.max(parseInt(req.query.skip || "0", 10), 0);

  try {
    const col = mongoose.connection.db.collection(collection);
    const docs = await col
      .find({})
      .sort({ _id: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    // stringify _id cho frontend dễ render
    const out = docs.map((d) => ({ ...d, _id: d?._id?.toString?.() || d._id }));
    res.json({ success: true, data: out, limit, skip });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.delete("/admin/mongo/:collection/:id", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  if (mongoose.connection?.readyState !== 1) {
    return res.json({ success: false, message: "Mongo chưa sẵn sàng" });
  }

  const { collection, id } = req.params;

  try {
    const col = mongoose.connection.db.collection(collection);
    const _id = mongoose.Types.ObjectId.isValid(id)
      ? new mongoose.Types.ObjectId(id)
      : id;

    const result = await col.deleteOne({ _id });
    res.json({ success: true, deletedCount: result.deletedCount || 0 });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// Proxy gọi Gemini (generateContent) để tránh lộ API key trên frontend
app.post("/admin/chatgpt", async (req, res) => {
  if (!requireAdmin(req, res)) return;

  const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
  if (!apiKey) {
    return res.status(500).json({
      success: false,
      message: "Thiếu GEMINI_API_KEY trong .env",
    });
  }

  try {
    const { messages, model, temperature, structured } = req.body || {};

    // Nếu frontend gửi model kiểu OpenAI (vd: gpt-*), tự fallback sang Gemini.
    const geminiModel =
      typeof model === "string" && model.trim().startsWith("gemini-")
        ? model.trim()
        : "gemini-2.5-flash";

    const safeText = (v) => (v === undefined || v === null ? "" : String(v));

    const arr = Array.isArray(messages)
      ? messages
      : [{ role: "user", content: safeText(req.body?.prompt || "") }];

    // Gom tất cả system message thành 1 system instruction
    const systemText = arr
      .filter((m) => m && m.role === "system")
      .map((m) => safeText(m.content).trim())
      .filter(Boolean)
      .join("\n");

    // Gemini roles: user | model
    const contents = arr
      .filter((m) => m && m.role !== "system")
      .map((m) => {
        const role = m.role === "assistant" ? "model" : "user";
        const text = safeText(m.content).trim() || " ";
        return { role, parts: [{ text }] };
      });

    const useStructured = structured === true;

    const securityReportSchema = {
      type: "object",
      additionalProperties: false,
      properties: {
        summary: { type: "string", description: "Tóm tắt tối đa 3 câu." },
        key_facts: {
          type: "array",
          items: { type: "string" },
          minItems: 3,
          maxItems: 8,
        },
        stats: {
          type: "object",
          additionalProperties: false,
          properties: {
            ip: { type: "string" },
            request_count: { type: "integer" },
            time_window_seconds: { type: "integer" },
            user_agent: { type: "string" },
            top_referers: {
              type: "array",
              items: { type: "string" },
              minItems: 0,
              maxItems: 8,
            },
            status_breakdown: {
              type: "object",
              additionalProperties: false,
              properties: {
                s2xx: { type: "integer" },
                s3xx: { type: "integer" },
                s4xx: { type: "integer" },
                s5xx: { type: "integer" },
              },
              required: ["s2xx", "s3xx", "s4xx", "s5xx"],
            },
          },
          required: [
            "ip",
            "request_count",
            "time_window_seconds",
            "user_agent",
            "top_referers",
            "status_breakdown",
          ],
        },
        admin_endpoints: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            properties: {
              path: { type: "string" },
              count: { type: "integer" },
              note: { type: "string" },
            },
            required: ["path", "count", "note"],
          },
        },
        risk: {
          type: "object",
          additionalProperties: false,
          properties: {
            level: { type: "string", enum: ["low", "medium", "high", "critical"] },
            score: { type: "integer", minimum: 0, maximum: 10 },
            reasons: {
              type: "array",
              items: { type: "string" },
              minItems: 2,
              maxItems: 8,
            },
          },
          required: ["level", "score", "reasons"],
        },
        actions: {
          type: "object",
          additionalProperties: false,
          properties: {
            immediate_24h: {
              type: "array",
              items: { type: "string" },
              minItems: 2,
              maxItems: 8,
            },
            short_7d: {
              type: "array",
              items: { type: "string" },
              minItems: 2,
              maxItems: 8,
            },
            long_30d: {
              type: "array",
              items: { type: "string" },
              minItems: 2,
              maxItems: 8,
            },
          },
          required: ["immediate_24h", "short_7d", "long_30d"],
        },
        limitations: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
          maxItems: 6,
        },
      },
      required: [
        "summary",
        "key_facts",
        "stats",
        "admin_endpoints",
        "risk",
        "actions",
        "limitations",
      ],
    };

    const structuredSystem = useStructured
      ? [
        "Bạn là chuyên gia SOC. Hãy phân tích logs/ngữ cảnh người dùng cung cấp.",
        "Chỉ dùng thông tin có trong dữ liệu; nếu thiếu thì ghi rõ trong limitations, KHÔNG bịa.",
        "Trả về ĐÚNG JSON theo schema được yêu cầu. Không thêm văn bản ngoài JSON.",
      ].join("\n")
      : "";

    const body = {
      contents,
      generationConfig: {
        temperature: typeof temperature === "number" ? temperature : 0.3,
        ...(useStructured
          ? {
            responseMimeType: "application/json",
            responseJsonSchema: securityReportSchema,
          }
          : {}),
      },
      ...((systemText || structuredSystem)
        ? {
          systemInstruction: {
            role: "system",
            parts: [{ text: [structuredSystem, systemText].filter(Boolean).join("\n") }],
          },
        }
        : {}),
    };

    const modelPath = geminiModel.startsWith("models/")
      ? geminiModel
      : `models/${geminiModel}`;

    const url = `https://generativelanguage.googleapis.com/v1beta/${modelPath}:generateContent?key=${apiKey}`;

    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      return res.status(response.status).json({
        success: false,
        message: data?.error?.message || data?.message || "Gemini API error",
        raw: data,
      });
    }

    const text =
      (data?.candidates?.[0]?.content?.parts || [])
        .map((p) => p?.text || "")
        .join("") || "";

    if (useStructured) {
      try {
        const json = JSON.parse(text);
        return res.json({
          success: true,
          kind: "structured",
          data: json,
          usage: data?.usageMetadata,
          model: geminiModel,
        });
      } catch (e) {
        // Fallback nếu vì lý do nào đó JSON bị lỗi
        return res.json({
          success: true,
          kind: "text",
          reply: text || "(empty)",
          parseError: e.message,
          usage: data?.usageMetadata,
          model: geminiModel,
        });
      }
    }

    res.json({
      success: true,
      kind: "text",
      reply: text || "(empty)",
      usage: data?.usageMetadata,
      model: geminiModel,
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});



app.listen(port, async () => {
  console.log(`✅ Server Cloudinary đang chạy tại http://localhost:${port}`);
  await connectMongo();
  await restoreFaceDBFromCloud();
});