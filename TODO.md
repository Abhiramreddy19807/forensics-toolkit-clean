# DAFT Enhancement TODO
Current: c:/Users/MOLE LABS/Desktop/forensics_toolkit

## Approved Plan Steps (Priority Order)

### 1. app.py Enhancements
- [ ] ADD globals (USERS/roles, stores, analytics)
- [ ] ADD decorators (@login_required, @role_required, @permission_required)
- [ ] MODIFY login(): Add session role/role_label
- [ ] ADD log_activity(), case mgmt funcs (create_case etc.)
- [ ] ADD evidence funcs (hashing, metadata, register_evidence)
- [ ] ADD new routes (/cases, /api/evidence/*, log-analysis etc.)
- [ ] ADD analysis stubs (deepfake etc.)
- [ ] MODIFY existing APIs: Add case_id, logging, register_evidence
- [ ] ADD RBAC to routes

### 2. Templates
- [ ] base.html: Role badge in sidebar
- [ ] evidence.html/image_analysis.html: Case dropdown

### 3. Test & Verify
- [ ] pip install -r requirements.txt
- [ ] python app.py
- [ ] Test login/roles/cases/hash/metadata/charts

**Next: Edit app.py (step-by-step)**
