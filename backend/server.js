const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const util = require('util');
const fs = require('fs');
const execPromise = util.promisify(exec);

const app = express();
const port = 8080;

app.use(cors());
app.use(express.json());

// Fabric 环境配置
const fabricPath = '/home/lqzmw/hyperledger-fabric/fabric-samples/test-network';
const peerCommand = `cd ${fabricPath} && export PATH=${fabricPath}/../bin:$PATH && export FABRIC_CFG_PATH=${fabricPath}/../config/ && export CORE_PEER_TLS_ENABLED=true && export CORE_PEER_LOCALMSPID="Org1MSP" && export CORE_PEER_TLS_ROOTCERT_FILE=${fabricPath}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt && export CORE_PEER_MSPCONFIGPATH=${fabricPath}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp && export CORE_PEER_ADDRESS=localhost:7051 && `;

// ========== 授权数据存储（实际应用应使用数据库） ==========
const authFile = './authorizations.json';
function loadAuths() {
    try {
        return JSON.parse(fs.readFileSync(authFile, 'utf8'));
    } catch (e) {
        return {}; // 格式: { "certId": { "毕业生姓名": "张三", "authorizedCompanies": ["公司A", "公司B"] } }
    }
}
function saveAuths(auths) {
    fs.writeFileSync(authFile, JSON.stringify(auths, null, 2));
}

// 脱敏函数
function maskIdCard(idCard) {
    if (!idCard || idCard.length < 10) return idCard;
    return idCard.substring(0, 6) + '******' + idCard.substring(idCard.length - 4);
}

// ========== API ==========

// 颁发证书
app.post('/api/certificates', async (req, res) => {
    const { certId, studentName, idCard, school, major } = req.body;
    
    if (!certId || !studentName || !school) {
        return res.status(400).json({ error: '缺少必要字段' });
    }
    
    const color = studentName;
    const size = parseInt(idCard) || 0;
    const owner = school;
    const appraisedValue = 1;
    
    const command = `${peerCommand} peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${fabricPath}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n basic --peerAddresses localhost:7051 --tlsRootCertFiles ${fabricPath}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${fabricPath}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"CreateAsset","Args":["${certId}","${color}","${size}","${owner}","${appraisedValue}"]}'`;
    
    try {
        await execPromise(command);
        // 初始化授权记录
        const auths = loadAuths();
        if (!auths[certId]) {
            auths[certId] = { studentName, authorizedCompanies: [] };
            saveAuths(auths);
        }
        res.json({ success: true, message: '证书已上链', data: { certId, studentName, school } });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 查询证书（带脱敏和权限控制）
app.get('/api/certificates/:certId', async (req, res) => {
    const certId = req.params.certId;
    const companyName = req.headers['x-company'] || ''; // 企业名称从请求头获取
    
    const command = `${peerCommand} peer chaincode query -C mychannel -n basic -c '{"function":"ReadAsset","Args":["${certId}"]}'`;
    
    try {
        const { stdout } = await execPromise(command);
        const data = JSON.parse(stdout);
        
        // 检查授权
        const auths = loadAuths();
        const auth = auths[certId];
        const isAuthorized = auth && auth.authorizedCompanies.includes(companyName);
        
        // 基础信息（所有人可见）
        let certificate = {
            certId: data.ID,
            studentName: data.Color,
            school: data.Owner,
            status: data.AppraisedValue === 1 ? 'active' : 'revoked',
            isValid: true
        };
        
        // 完整信息（仅授权企业可见）
        if (isAuthorized) {
            certificate.idCard = data.Size.toString();
            certificate.detailLevel = 'full';
        } else {
            certificate.idCard = maskIdCard(data.Size.toString());
            certificate.detailLevel = 'masked';
            certificate.message = companyName ? '当前企业未获得授权，仅显示脱敏信息' : '请提供企业名称以获取完整信息';
        }
        
        res.json({ success: true, certificate });
    } catch (error) {
        res.status(404).json({ error: '证书不存在' });
    }
});

// 批量核验
app.post('/api/certificates/batch-verify', async (req, res) => {
    const { certIds, companyName } = req.body;
    
    if (!certIds || !Array.isArray(certIds) || certIds.length === 0) {
        return res.status(400).json({ error: '请提供证书编号数组' });
    }
    
    const results = [];
    for (const certId of certIds) {
        try {
            const command = `${peerCommand} peer chaincode query -C mychannel -n basic -c '{"function":"ReadAsset","Args":["${certId}"]}'`;
            const { stdout } = await execPromise(command);
            const data = JSON.parse(stdout);
            
            const auths = loadAuths();
            const auth = auths[certId];
            const isAuthorized = auth && auth.authorizedCompanies.includes(companyName);
            
            results.push({
                certId,
                studentName: data.Color,
                school: data.Owner,
                status: data.AppraisedValue === 1 ? 'active' : 'revoked',
                idCard: isAuthorized ? data.Size.toString() : maskIdCard(data.Size.toString()),
                isValid: true
            });
        } catch (error) {
            results.push({ certId, isValid: false, error: '证书不存在' });
        }
    }
    
    res.json({ success: true, total: certIds.length, valid: results.filter(r => r.isValid).length, results });
});

// 设置授权（毕业生端）
app.post('/api/auth/authorize', (req, res) => {
    const { certId, studentName, companyName, action } = req.body; // action: 'add' 或 'remove'
    
    const auths = loadAuths();
    if (!auths[certId]) {
        auths[certId] = { studentName, authorizedCompanies: [] };
    }
    
    if (action === 'add') {
        if (!auths[certId].authorizedCompanies.includes(companyName)) {
            auths[certId].authorizedCompanies.push(companyName);
        }
    } else if (action === 'remove') {
        auths[certId].authorizedCompanies = auths[certId].authorizedCompanies.filter(c => c !== companyName);
    }
    
    saveAuths(auths);
    res.json({ success: true, authorizedCompanies: auths[certId].authorizedCompanies });
});

// 查询授权列表（毕业生端）
app.get('/api/auth/:certId', (req, res) => {
    const certId = req.params.certId;
    const auths = loadAuths();
    res.json({ success: true, authorizedCompanies: auths[certId]?.authorizedCompanies || [] });
});

// 获取所有证书（带脱敏）
app.get('/api/certificates', async (req, res) => {
    const command = `${peerCommand} peer chaincode query -C mychannel -n basic -c '{"function":"GetAllAssets","Args":[]}'`;
    
    try {
        const { stdout } = await execPromise(command);
        const assets = JSON.parse(stdout);
        const certificates = assets.map(asset => ({
            certId: asset.ID,
            studentName: asset.Color,
            school: asset.Owner,
            status: asset.AppraisedValue === 1 ? 'active' : 'revoked'
        }));
        res.json({ success: true, certificates });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`服务器运行在 http://localhost:${port}`);
});