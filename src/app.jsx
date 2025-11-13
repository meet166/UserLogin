import React, { useState } from "react";
import "bootstrap/dist/css/bootstrap.min.css";
import "./App.css"; // import the CSS
import { Toast, ToastContainer } from "react-bootstrap";

function App() {
  const [authToken, setAuthToken] = useState(null);
  const [showToast, setShowToast] = useState(false);
  const [data, setData] = useState([]);
  const [parentId, setParentId] = useState("");
  const [page, setPage] = useState("");
  const [pageSize, setPageSize] = useState("");

  const login = async (e) => {
    e.preventDefault();
    const name = e.target.name.value;
    const email = e.target.email.value;
    const password = e.target.password.value;

    try {
      const res = await fetch("http://127.0.0.1:8000/user/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password }),
      });
      const result = await res.json();

      if (res.ok) {
        setAuthToken(result.token);
        setShowToast(true);
      } else {
        alert(result.detail || "Login failed.");
      }
    } catch (err) {
      console.error(err);
      alert("Error connecting to backend");
    }
  };

const fetchData = async (endpoint, pagination = false) => {
  if (!authToken) return alert("Login first!");
  try {
    let url = `http://127.0.0.1:8000/${endpoint}`;
    if (pagination) {
      if (!page || !pageSize) return alert("Enter Page & Page Size");
      url += `?page=${page}&page_size=${pageSize}`;
    }

    const res = await fetch(url, { headers: { Authorization: `Bearer ${authToken}` } });
    const result = await res.json();
    let rawData = result.data || result;

    // Correct flatten for nested categories
    const flattenNested = (arr, parentName = "") => {
      if (!Array.isArray(arr)) return [];
      let flat = [];
      arr.forEach(item => {
        // If children key exists, flatten recursively
        const { children, ...rest } = item;
        const displayName = parentName ? `${parentName} > ${rest.name || ""}` : rest.name || "";
        flat.push({ ...rest, name: displayName });
        if (children && Array.isArray(children) && children.length > 0) {
          flat = flat.concat(flattenNested(children, displayName));
        }
      });
      return flat;
    };

    // If endpoint is nested, flatten it
    if (endpoint.toLowerCase().includes("nested")) {
      setData(flattenNested(rawData));
    } else {
      setData(rawData);
    }
  } catch (err) {
    console.error(err);
    alert(`Error fetching ${endpoint}`);
  }
};

  const renderTable = () => {
    if (!data.length) return <p className="text-center text-muted">No data found.</p>;
    const headers = Object.keys(data[0]);
    return (
      <table className="table table-striped table-bordered table-hover">
        <thead className="custom-table-header">
          <tr>{headers.map((h) => <th key={h}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {data.map((row, idx) => (
            <tr key={idx}>
              {headers.map((h) => <td key={h}>{row[h] ?? ""}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    );
  };

  if (!authToken) {
    return (
      <div className="d-flex justify-content-center align-items-center vh-100" style={{ backgroundColor: "#f8f9fa" }}>
        <form onSubmit={login} className="card p-4 shadow-sm" style={{ width: "400px", borderRadius: "16px" }}>
          <h2 className="mb-3 text-center fw-bold">Login</h2>
          <input type="text" name="name" className="form-control mb-3" placeholder="Name" required />
          <input type="email" name="email" className="form-control mb-3" placeholder="Email" required />
          <input type="password" name="password" className="form-control mb-3" placeholder="Password" required />
          <button type="submit" className="gradient-btn">Login</button>
        </form>
      </div>
    );
  }

  return (
    <div className="container-fluid mt-4">
      <ToastContainer className="p-3" position="top-center">
        <Toast show={showToast} onClose={() => setShowToast(false)} delay={3000} autohide bg="success">
          <Toast.Body className="text-white fw-bold">✅ Login Successful!</Toast.Body>
        </Toast>
      </ToastContainer>

      <div className="d-flex flex-wrap gap-2 mb-3">
        {[
          { label: "Brands", endpoint: "auth/getAllBrands" },
          { label: "Category", endpoint: "auth/getAllCategories" },
          { label: "Category by Nested", endpoint: "auth/getAllCategoriesByNested" },
          { label: "Category by Page", endpoint: "auth/getCategoryByPagesLimit", pagination: true },
          { label: "Product by Page", endpoint: "auth/getProductByPagesLimit", pagination: true },
          { label: "Attributes", endpoint: "auth/getAllAttributes" },
          { label: "Attribute Group", endpoint: "auth/getAllAttributeGroup" },
          { label: "Merge Products", endpoint: "auth/getMergerAllProduct" }
        ].map((btn) => (
          <button
            key={btn.label}
            className="gradient-btn flex-grow-1"
            onClick={() => fetchData(btn.endpoint, btn.pagination)}
          >
            {btn.label}
          </button>
        ))}
      </div>

      <div className="d-flex gap-2 mb-3">
        <input type="number" className="form-control" placeholder="Page" value={page} onChange={(e) => setPage(e.target.value)} />
        <input type="number" className="form-control" placeholder="Page Size" value={pageSize} onChange={(e) => setPageSize(e.target.value)} />
      </div>

      <div className="d-flex gap-2 mb-3">
        <input type="number" className="form-control" placeholder="Parent ID" value={parentId} onChange={(e) => setParentId(e.target.value)} />
        <button className="gradient-btn flex-grow-1" onClick={() => {
          if (!parentId) return alert("Enter Parent ID");
          fetchData(`auth/getCategoryByParentID?parent_id=${parentId}`);
        }}>Category by ParentID</button>
      </div>

      <div className="table-responsive">{renderTable()}</div>
    </div>
  );
}

export default App;
