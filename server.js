const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors()); 
const PORT = 3000;

const db = new sqlite3.Database("banco-de-dados.db");

db.serialize(() => {
  db.run(
    "CREATE TABLE IF NOT EXISTS tarefas (id INTEGER PRIMARY KEY, tarefa TEXT)"
  );
});

db.serialize(() => {
  db.run(
    "CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)"
  );
});

app.use(express.json());

const verificarToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ error: "Nenhum token fornecido." });
  }
  jwt.verify(token.split(" ")[1], "secreto", (err, decoded) => {
    if (err) {
      return res.status(500).json({ error: "Falha ao autenticar o token." });
    }
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};

app.post("/tarefas", verificarToken, (req, res) => {
  const { tarefa } = req.body;
  db.run("INSERT INTO tarefas (tarefa) VALUES (?)", [tarefa], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ id: this.lastID, tarefa });
  });
});

app.get("/tarefas", verificarToken, (req, res) => {
  db.all("SELECT * FROM tarefas", [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json(rows);
  });
});

app.get("/tarefas/:id", verificarToken, (req, res) => {
  const { id } = req.params;
  db.get("SELECT * FROM tarefas WHERE id = ?", [id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (row) {
      res.status(200).json(row);
    } else {
      res.status(404).json({ error: "Tarefa não encontrada!" });
    }
  });
});

app.put("/tarefas/:id", verificarToken, (req, res) => {
  const { id } = req.params;
  const { tarefa } = req.body;
  db.run(
    "UPDATE tarefas SET tarefa = ? WHERE id = ?",
    [tarefa, id],
    function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (this.changes) {
        res.status(200).json({ message: "Tarefa atualizada com sucesso!" });
      } else {
        res.status(404).json({ error: "Tarefa não encontrada!" });
      }
    }
  );
});

app.delete("/tarefas/:id", verificarToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM tarefas WHERE id = ?", [id], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes) {
      res.status(200).json({ message: "Tarefa removida com sucesso!" });
    } else {
      res.status(404).json({ error: "Tarefa não encontrada!" });
    }
  });
});

app.post("/registro", async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const usuarioExistente = await buscarUsuario(username);
    if (usuarioExistente) {
      return res.status(400).json({ error: "Usuário já registrado" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await criarUsuario(username, hashedPassword, role);
    res.status(201).json({ message: "Usuário registrado com sucesso" });
  } catch (error) {
    console.error("Erro no registro:", error);
    res.status(500).json({ error: "Erro no registro de usuário" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const usuario = await buscarUsuario(username);
    if (!usuario) {
      return res.status(401).json({ error: "Usuário não encontrado" });
    }
    const senhaValida = await bcrypt.compare(password, usuario.password);
    if (!senhaValida) {
      return res.status(401).json({ error: "Senha incorreta" });
    }
    const token = jwt.sign(
      { id: usuario.id, username: usuario.username, role: usuario.role },
      "secreto",
      { expiresIn: "1h" }
    );
    res.status(200).json({ token });
  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).json({ error: "Erro no login de usuário" });
  }
});

const buscarUsuario = (username) => {
  return new Promise((resolve, reject) => {
    db.get(
      "SELECT * FROM usuarios WHERE username = ?",
      [username],
      (err, row) => {
        if (err) {
          reject(err);
        }
        resolve(row);
      }
    );
  });
};

const criarUsuario = (username, password, role) => {
  return new Promise((resolve, reject) => {
    db.run(
      "INSERT INTO usuarios (username, password, role) VALUES (?, ?, ?)",
      [username, password, role],
      (err) => {
        if (err) {
          reject(err);
        }
        resolve();
      }
    );
  });
};

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta http://localhost:${PORT}`);
});
