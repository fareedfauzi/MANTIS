/**
 * Metis – Hệ thống dịch tiếng Việt toàn diện
 * Fork của MANTIS (https://github.com/fareedfauzi/MANTIS) bởi fareedfauzi
 *
 * Dùng MutationObserver để tự động dịch TẤT CẢ nội dung UI khi DOM thay đổi,
 * bao gồm cả nội dung động được tạo bởi app.js.
 */

(function () {
  'use strict';

  // ─── Từ điển dịch Anh → Việt ────────────────────────────────────────────────
  const VI = {

    // ── Tên app & nhãn chính ───────────────────────────────────────────────────
    'MANTIS': 'Metis',
    'MANTIS AI': 'Metis AI',
    'Multi-source Analysis & Threat Intelligence Search': 'Phân tích Đa nguồn & Tình báo Mối đe dọa',
    'Multi-source Analysis and Threat Intelligence Search': 'Phân tích Đa nguồn & Tình báo Mối đe dọa',

    // ── Điều hướng sidebar ─────────────────────────────────────────────────────
    'Home': 'Trang chủ',
    'IOC Intelligence': 'Tình báo IOC',
    'IOC Search': 'Tìm kiếm IOC',
    'History Lookups': 'Lịch sử tra cứu',
    'Threat Knowledge': 'Kiến thức Mối đe dọa',
    "Today's Intelligence": 'Tình báo Hôm nay',
    'Threat Actor': 'Tác nhân Đe dọa',
    'Malware & Tools': 'Phần mềm Độc hại & Công cụ',
    'Ransomware Monitor': 'Giám sát Ransomware',
    'Rule Explorer': 'Khám phá Quy tắc',
    'Sample Scanner': 'Quét Mẫu',
    'Rule Workbench': 'Bàn làm việc YARA',
    'Similarity': 'Tương đồng',
    'Dashboard': 'Bảng điều khiển',
    'All Entities': 'Tất cả Thực thể',
    'Create Entity': 'Tạo Thực thể',
    'Compare Sample': 'So sánh Mẫu',
    'Settings': 'Cài đặt',
    'CTI Articles': 'Bài báo CTI',
    'Vulnerability Intelligence': 'Tình báo Lỗ hổng',
    'X Monitor': 'Theo dõi X',
    'Breach Watcher': 'Giám sát Rò rỉ',
    'Reverse Engineering': 'Dịch ngược',
    'AI Binary Analysis Lab': 'Phòng thí nghiệm Phân tích Nhị phân AI',
    'Samples Downloader': 'Tải xuống Mẫu',
    'VT Samples Downloader': 'Tải mẫu từ VT',
    'Telegram Toolkit': 'Bộ công cụ Telegram',
    'Channel Monitor': 'Giám sát Kênh',
    'Telegram Auth Settings': 'Cài đặt Xác thực Telegram',
    'Bot Info': 'Thông tin Bot',
    'Dump Messages': 'Xuất Tin nhắn',
    'Surveillance Vendor': 'Nhà cung cấp Giám sát',

    // ── Cài đặt ────────────────────────────────────────────────────────────────
    'API Keys': 'Khóa API',
    'Threat Feeds': 'Nguồn cấp Đe dọa',
    'GitHub Repos': 'Kho GitHub',
    'Manage Threat Feeds': 'Quản lý Nguồn cấp Đe dọa',
    'Free / Built-in Sources': 'Nguồn miễn phí / Tích hợp sẵn',
    'AI Provider': 'Nhà cung cấp AI',
    'AI Model': 'Mô hình AI',
    'Timeout (s)': 'Thời gian chờ (giây)',
    'Test Connection': 'Kiểm tra kết nối',
    'Connection successful': 'Kết nối thành công',
    'Save Settings': 'Lưu Cài đặt',
    'Saved': 'Đã lưu',
    'Clear Stored Key': 'Xóa khóa đã lưu',
    'API base URL': 'URL API cơ sở',
    'Select All': 'Chọn tất cả',
    'Deselect All': 'Bỏ chọn tất cả',
    'Sync Directory': 'Đồng bộ Thư mục',
    'Manage Categories': 'Quản lý Danh mục',
    'Configure pipeline': 'Cấu hình quy trình',
    'Default Pipeline': 'Quy trình mặc định',
    'Default Disassembler': 'Trình dịch hợp ngữ mặc định',
    'CLI executable': 'Tệp thực thi CLI',
    'Default': 'Mặc định',
    'Availability Checks': 'Kiểm tra khả dụng',
    'Engine Settings': 'Cài đặt Engine',

    // ── Nút bấm phổ biến ───────────────────────────────────────────────────────
    'Search': 'Tìm kiếm',
    'Reset': 'Đặt lại',
    'Refresh': 'Làm mới',
    'Save': 'Lưu',
    'Save Results': 'Lưu Kết quả',
    'Import JSON': 'Nhập JSON',
    'Export': 'Xuất',
    'Export MD': 'Xuất Markdown',
    'Export JSON': 'Xuất JSON',
    'Export CSV': 'Xuất CSV',
    'All': 'Tất cả',
    'None': 'Không chọn',
    'Apply': 'Áp dụng',
    'Clear': 'Xóa',
    'Clear History': 'Xóa Lịch sử',
    'Clear Query': 'Xóa truy vấn',
    'Close': 'Đóng',
    'Close Preview': 'Đóng xem trước',
    'Cancel': 'Hủy',
    'Delete': 'Xóa',
    'Edit': 'Chỉnh sửa',
    'Copy': 'Sao chép',
    'Download': 'Tải xuống',
    'Upload': 'Tải lên',
    'Browse': 'Duyệt',
    'Browse files': 'Duyệt tệp',
    'Open': 'Mở',
    'Add': 'Thêm',
    'Remove': 'Xóa bỏ',
    'Create': 'Tạo',
    'Update': 'Cập nhật',
    'Enable': 'Bật',
    'Disable': 'Tắt',
    'Validate': 'Xác thực',
    'Run': 'Chạy',
    'Stop': 'Dừng',
    'Resume': 'Tiếp tục',
    'Retry': 'Thử lại',
    'Confirm': 'Xác nhận',
    'Submit': 'Gửi',
    'Send': 'Gửi',
    'Next': 'Tiếp theo',
    'Back': 'Quay lại',
    'Previous': 'Trước',
    'Load More': 'Tải thêm',
    'Show More': 'Xem thêm',
    'Show Less': 'Thu gọn',
    'Expand': 'Mở rộng',
    'Collapse': 'Thu gọn',
    'Copy Address': 'Sao chép địa chỉ',
    'Copy Log': 'Sao chép nhật ký',
    'Apply to Editor': 'Áp dụng vào Editor',
    'Add Samples': 'Thêm Mẫu',
    'Add feed': 'Thêm nguồn cấp',
    'Add to Watchlist': 'Thêm vào danh sách theo dõi',
    'Add Watchlist Entry': 'Thêm mục theo dõi',
    'Add User': 'Thêm người dùng',
    'View Details': 'Xem chi tiết',
    'View All': 'Xem tất cả',
    'Manage Accounts': 'Quản lý Tài khoản',
    'Manage API Keys': 'Quản lý Khóa API',
    'Read interactive report modal': 'Đọc báo cáo tương tác',
    'Open report in new browser tab': 'Mở báo cáo trong tab mới',
    'Delete report': 'Xóa báo cáo',
    'Start Download': 'Bắt đầu Tải xuống',
    'Select Folder': 'Chọn Thư mục',
    'Copy Failed': 'Sao chép Thất bại',
    'Copy Success': 'Sao chép Thành công',
    'AI Daily Brief': 'Tóm tắt AI Hàng ngày',
    'Create Report (AI)': 'Tạo Báo cáo (AI)',
    'Refresh Recent': 'Làm mới Gần đây',
    'Correlate Candidates': 'Tương quan Ứng viên',
    'Analyze AI Workspace': 'Phân tích AI Workspace',
    'Analyze a local path': 'Phân tích đường dẫn cục bộ',
    'Decompile and export': 'Dịch ngược và xuất',
    'Create Case': 'Tạo Vụ việc',
    'Sync Case': 'Đồng bộ Vụ việc',
    'Next Step': 'Bước tiếp theo',
    'Run Next': 'Chạy tiếp',
    'Assess': 'Đánh giá',
    'Assess Evidence': 'Đánh giá Bằng chứng',
    'Report': 'Báo cáo',
    'Draft Report': 'Soạn Báo cáo',
    'Open AI Panel': 'Mở bảng AI',
    'Hunt Infra': 'Săn Hạ tầng',
    'Preview': 'Xem trước',
    'Compare Relationship': 'So sánh Mối quan hệ',
    'Recommend Pivots': 'Đề xuất Hướng điều tra',
    'Summarize Findings': 'Tóm tắt Kết quả',
    'Agent Investigation': 'Điều tra Tự động',
    'Attribution': 'Quy trách nhiệm',
    'Assist': 'Hỗ trợ',
    'Browse All (Recent)': 'Xem tất cả (Gần đây)',

    // ── Tab IOC search ─────────────────────────────────────────────────────────
    'Auto-Detect': 'Tự động',
    'Hash': 'Mã băm',
    'Domain': 'Tên miền',
    'IP': 'Địa chỉ IP',
    'URL': 'URL',
    'Keyword': 'Từ khóa',
    'Infra': 'Hạ tầng',
    'Auto': 'Tự động',
    'Sources': 'Nguồn dữ liệu',

    // ── Trạng thái / Status ────────────────────────────────────────────────────
    'Loading...': 'Đang tải...',
    'Loading': 'Đang tải',
    'Searching...': 'Đang tìm kiếm...',
    'Processing...': 'Đang xử lý...',
    'Analyzing...': 'Đang phân tích...',
    'Summarizing': 'Đang tóm tắt...',
    'Recommending': 'Đang đề xuất...',
    'Finding passive pivots...': 'Đang tìm hướng điều tra...',
    'Summarizing source result...': 'Đang tóm tắt kết quả nguồn...',
    'Comparing relationship': 'Đang so sánh mối quan hệ...',
    'Complete': 'Hoàn thành',
    'Completed': 'Đã hoàn thành',
    'Failed': 'Thất bại',
    'Error': 'Lỗi',
    'Success': 'Thành công',
    'Active': 'Đang hoạt động',
    'Inactive': 'Không hoạt động',
    'Pending': 'Đang chờ',
    'Running': 'Đang chạy',
    'Queued': 'Trong hàng đợi',
    'Cancelled': 'Đã hủy',
    'Archived': 'Đã lưu trữ',
    'Available': 'Khả dụng',
    'Not available': 'Không khả dụng',
    'Enabled': 'Đã bật',
    'Disabled': 'Đã tắt',
    'Unknown': 'Không xác định',
    'None': 'Không có',
    'Yes': 'Có',
    'No': 'Không',
    'No data': 'Không có dữ liệu',
    'No results': 'Không có kết quả',
    'Not found': 'Không tìm thấy',
    'No records found': 'Không tìm thấy bản ghi',
    'No items': 'Không có mục nào',
    'Empty': 'Trống',
    'Server error': 'Lỗi máy chủ',
    'Search failed': 'Tìm kiếm thất bại',
    'AI processing failed': 'Xử lý AI thất bại',
    'AI report failed': 'Báo cáo AI thất bại',
    'AI summary failed': 'Tóm tắt AI thất bại',
    'Metis AI is unavailable.': 'Metis AI không khả dụng.',
    'Failed to fetch bot info': 'Không thể lấy thông tin bot',
    'Does not compile.': 'Không biên dịch được.',
    'AI processing failed': 'Xử lý AI thất bại',

    // ── Nhãn chung ─────────────────────────────────────────────────────────────
    'Name': 'Tên',
    'Type': 'Loại',
    'Status': 'Trạng thái',
    'Details': 'Chi tiết',
    'Description': 'Mô tả',
    'Detail': 'Chi tiết',
    'Date': 'Ngày',
    'Time': 'Thời gian',
    'Source': 'Nguồn',
    'Sources': 'Các nguồn',
    'Tags': 'Nhãn',
    'Score': 'Điểm',
    'Count': 'Số lượng',
    'Size': 'Kích thước',
    'Version': 'Phiên bản',
    'Action': 'Hành động',
    'Actions': 'Hành động',
    'Category': 'Danh mục',
    'Categories': 'Danh mục',
    'Country': 'Quốc gia',
    'Countries': 'Quốc gia',
    'Region': 'Vùng',
    'Sector': 'Lĩnh vực',
    'Group': 'Nhóm',
    'Actor': 'Tác nhân',
    'Actors': 'Tác nhân',
    'Family': 'Họ',
    'Campaign': 'Chiến dịch',
    'Aliases': 'Bí danh',
    'References': 'Tài liệu tham khảo',
    'Links': 'Liên kết',
    'Hash': 'Mã băm',
    'MD5': 'MD5',
    'SHA1': 'SHA-1',
    'SHA256': 'SHA-256',
    'File': 'Tệp',
    'Files': 'Tệp',
    'Size': 'Kích thước',
    'Path': 'Đường dẫn',
    'Address': 'Địa chỉ',
    'Port': 'Cổng',
    'Protocol': 'Giao thức',
    'Banner': 'Banner',
    'Certificate': 'Chứng chỉ',
    'Organization': 'Tổ chức',
    'Email': 'Email',
    'Phone': 'Điện thoại',
    'Username': 'Tên người dùng',
    'Password': 'Mật khẩu',
    'Token': 'Token',
    'Key': 'Khóa',
    'Value': 'Giá trị',
    'Comment': 'Bình luận',
    'Note': 'Ghi chú',
    'Title': 'Tiêu đề',
    'Content': 'Nội dung',
    'Summary': 'Tóm tắt',
    'Report': 'Báo cáo',
    'Result': 'Kết quả',
    'Results': 'Kết quả',
    'Evidence': 'Bằng chứng',
    'Context': 'Ngữ cảnh',
    'Confidence': 'Độ tin cậy',
    'Severity': 'Mức độ nghiêm trọng',
    'Priority': 'Ưu tiên',
    'Impact': 'Tác động',
    'Risk': 'Rủi ro',
    'Threat': 'Mối đe dọa',
    'Malware': 'Phần mềm độc hại',
    'Ransomware': 'Ransomware',
    'Vulnerability': 'Lỗ hổng',
    'Exploit': 'Khai thác',
    'Indicator': 'Chỉ số',
    'IOC': 'IOC',
    'TTP': 'TTP',
    'CVE': 'CVE',
    'CVSS': 'CVSS',
    'PoC': 'PoC',
    'Infrastructure': 'Cơ sở hạ tầng',
    'Network': 'Mạng',
    'Domain': 'Tên miền',
    'Subdomain': 'Tên miền phụ',
    'IP Address': 'Địa chỉ IP',
    'ASN': 'ASN',
    'CIDR': 'CIDR',
    'Artifact': 'Tạo tác',
    'Artifacts': 'Tạo tác',
    'Sample': 'Mẫu',
    'Samples': 'Mẫu',
    'Binary': 'Nhị phân',
    'Function': 'Hàm',
    'Functions': 'Hàm',
    'Variable': 'Biến',
    'Variables': 'Biến',
    'String': 'Chuỗi',
    'Strings': 'Chuỗi',
    'Import': 'Nhập',
    'Imports': 'Hàm nhập',
    'Export': 'Xuất',
    'Exports': 'Hàm xuất',
    'Section': 'Phân mục',
    'Sections': 'Phân mục',
    'Header': 'Tiêu đề',
    'Headers': 'Tiêu đề',
    'Architecture': 'Kiến trúc',
    'Platform': 'Nền tảng',
    'Compiler': 'Trình biên dịch',
    'Packer': 'Đóng gói',
    'Signature': 'Chữ ký',
    'Rule': 'Quy tắc',
    'Rules': 'Quy tắc',
    'Match': 'Khớp',
    'Matches': 'Khớp',
    'Detection': 'Phát hiện',
    'Detections': 'Phát hiện',
    'Reputation': 'Danh tiếng',
    'Scan': 'Quét',
    'Analysis': 'Phân tích',
    'Investigation': 'Điều tra',
    'Case': 'Vụ việc',
    'Cases': 'Vụ việc',
    'Feed': 'Nguồn cấp',
    'Feeds': 'Nguồn cấp',
    'Article': 'Bài báo',
    'Articles': 'Bài báo',
    'Post': 'Bài đăng',
    'Posts': 'Bài đăng',
    'Channel': 'Kênh',
    'Channels': 'Kênh',
    'Bot': 'Bot',
    'Message': 'Tin nhắn',
    'Messages': 'Tin nhắn',
    'Victim': 'Nạn nhân',
    'Victims': 'Nạn nhân',
    'Attacker': 'Kẻ tấn công',
    'Target': 'Mục tiêu',
    'Targets': 'Mục tiêu',
    'Watchlist': 'Danh sách theo dõi',
    'History': 'Lịch sử',
    'Log': 'Nhật ký',
    'Logs': 'Nhật ký',
    'Event': 'Sự kiện',
    'Events': 'Sự kiện',
    'Timeline': 'Dòng thời gian',
    'Graph': 'Đồ thị',
    'Chart': 'Biểu đồ',
    'Map': 'Bản đồ',
    'List': 'Danh sách',
    'Table': 'Bảng',
    'Filter': 'Bộ lọc',
    'Sort': 'Sắp xếp',
    'Search': 'Tìm kiếm',
    'Query': 'Truy vấn',
    'Pivot': 'Hướng điều tra',
    'Pivots': 'Hướng điều tra',
    'Observation': 'Quan sát',
    'Observations': 'Quan sát',
    'Relationship': 'Mối quan hệ',
    'Relationships': 'Mối quan hệ',
    'Contradiction': 'Mâu thuẫn',
    'Contradicting': 'Mâu thuẫn',
    'Correlated Evidence': 'Bằng chứng tương quan',
    'Correlation': 'Tương quan',
    'Job': 'Công việc',
    'Jobs': 'Công việc',
    'Queue': 'Hàng đợi',
    'Progress': 'Tiến độ',
    'Output': 'Đầu ra',
    'Input': 'Đầu vào',
    'Config': 'Cấu hình',
    'Configuration': 'Cấu hình',
    'Pipeline': 'Quy trình',
    'Workflow': 'Luồng công việc',
    'Dashboard': 'Bảng điều khiển',
    'Overview': 'Tổng quan',

    // ── IOC Search & kết quả ───────────────────────────────────────────────────
    'IOC Intelligence Search': 'Tìm kiếm Tình báo IOC',
    'Enter an IOC above to begin the intelligence lookup.': 'Nhập IOC ở trên để bắt đầu tra cứu.',
    'No results found': 'Không tìm thấy kết quả',
    'No data available': 'Không có dữ liệu',
    'All Sources': 'Tất cả Nguồn',
    'Source Selector': 'Chọn Nguồn',
    'Auto-detect type from your input': 'Tự động nhận diện loại từ đầu vào',
    'Hash lookup (MD5, SHA-1, SHA-256, SHA-512, SHA3-384)': 'Tra cứu Mã băm (MD5, SHA-1, SHA-256...)',
    'Domain lookup': 'Tra cứu Tên miền',
    'IP address lookup': 'Tra cứu Địa chỉ IP',
    'URL lookup': 'Tra cứu URL',
    'Keyword / tag / indicator lookup': 'Tra cứu Từ khóa / nhãn / chỉ số',
    'Infrastructure search (IP, Domain, ASN, Port)': 'Tìm kiếm Hạ tầng (IP, Domain, ASN, Port)',
    'Search mode': 'Chế độ tìm kiếm',
    'Reputation': 'Danh tiếng',
    'Detections': 'Phát hiện',
    'Malware Family': 'Họ Phần mềm Độc hại',
    'Related Samples': 'Mẫu liên quan',
    'Passive DNS': 'DNS Thụ động',
    'Certificates': 'Chứng chỉ',
    'Network Infrastructure': 'Hạ tầng Mạng',
    'Sandbox Analysis': 'Phân tích Sandbox',
    'Threat Intelligence': 'Tình báo Mối đe dọa',
    'Open in new tab': 'Mở trong tab mới',
    'Pivot': 'Điều tra tiếp',
    'View cached results without re-querying': 'Xem kết quả đã cache',
    'Keyword search': 'Tìm kiếm từ khóa',
    'View CVE Details in NVD': 'Xem chi tiết CVE trong NVD',
    'View ORKL actor profile': 'Xem hồ sơ tác nhân ORKL',
    'View author profile (passive lookup)': 'Xem hồ sơ tác giả (tra cứu thụ động)',
    'Open @{user} on X': 'Mở @{user} trên X',
    'Open media': 'Mở media',
    'Open media link': 'Mở liên kết media',
    'Open original post on X': 'Mở bài đăng gốc trên X',
    'Self-reported profile location, not verified': 'Vị trí tự khai báo, chưa xác minh',
    'Self-reported, not verified': 'Tự khai báo, chưa xác minh',
    'Not included in this Validin plan': 'Không có trong gói Validin này',
    'Requires Kaspersky TIP API Key in Settings': 'Cần Khóa API Kaspersky TIP trong Cài đặt',
    'Pivot on certificate fingerprint': 'Điều tra qua dấu vân tay chứng chỉ',
    'Copy JARM': 'Sao chép JARM',
    'Copy Favicon MD5': 'Sao chép MD5 Favicon',

    // ── Lịch sử tra cứu ───────────────────────────────────────────────────────
    'History': 'Lịch sử',
    'AI Reports': 'Báo cáo AI',
    'No history yet': 'Chưa có lịch sử',
    'Clear all history': 'Xóa tất cả lịch sử',
    'Lookup History': 'Lịch sử Tra cứu',
    'Recent Searches': 'Tìm kiếm Gần đây',

    // ── Tình báo hôm nay ───────────────────────────────────────────────────────
    "Today's Intelligence": 'Tình báo Hôm nay',
    'Daily analyst workflow': 'Quy trình hàng ngày',
    'CTI articles, exploited vulnerabilities, new PoCs, ransomware victims, and current actor or malware mentions in one triage queue.': 'Bài báo CTI, lỗ hổng bị khai thác, PoC mới, nạn nhân ransomware và tác nhân trong một hàng đợi.',
    'AI Intelligence Report': 'Báo cáo Tình báo AI',
    'AI Analyst Brief': 'Tóm tắt Nhà phân tích AI',
    'Analyst Workflow': 'Quy trình Nhà phân tích',
    'Autonomous AI Investigation': 'Điều tra AI Tự động',
    'Today': 'Hôm nay',
    'Past 24H': '24 giờ qua',
    'Past 7D': '7 ngày qua',
    'Past 30D': '30 ngày qua',
    'All source types': 'Tất cả loại nguồn',
    'Analyst CTI': 'CTI Nhà phân tích',
    'Media / news': 'Truyền thông / Tin tức',
    'Vendor research': 'Nghiên cứu Nhà cung cấp',
    'Government / CERT': 'Chính phủ / CERT',
    'Community': 'Cộng đồng',
    'All severities': 'Tất cả mức độ',
    'Critical': 'Nghiêm trọng',
    'High': 'Cao',
    'Medium': 'Trung bình',
    'Low': 'Thấp',
    'Loading today\'s intelligence...': 'Đang tải tình báo hôm nay...',
    'Loading X Monitor...': 'Đang tải X Monitor...',
    'Loading similarity engine...': 'Đang tải công cụ tương đồng...',
    'Loading Binary Analysis engine...': 'Đang tải công cụ phân tích nhị phân...',
    'No active evidence loaded.': 'Chưa tải bằng chứng nào.',
    'Current Investigation': 'Điều tra Hiện tại',

    // ── Giám sát Ransomware ────────────────────────────────────────────────────
    'Ransomware Intelligence Monitor': 'Giám sát Tình báo Ransomware',
    'Threat Intelligence Aggregator': 'Tổng hợp Tình báo Mối đe dọa',
    'Analyze ransomware groups, victimology, and associated infrastructure using aggregated intelligence from multiple CTI sources.': 'Phân tích nhóm ransomware, nạn nhân và hạ tầng liên quan từ nhiều nguồn CTI.',
    'Active Ransomware Groups': 'Nhóm Ransomware Đang hoạt động',
    'Active Groups': 'Nhóm Đang hoạt động',
    'Recent Victims': 'Nạn nhân Gần đây',
    'Ransomware Groups': 'Nhóm Ransomware',
    'Activity & Trends': 'Hoạt động & Xu hướng',
    'Regions & Countries': 'Khu vực & Quốc gia',
    'Ransom Notes': 'Thông điệp Tống tiền',
    'Crypto Addresses': 'Địa chỉ Tiền mã hóa',
    'Last 7 Days': '7 ngày qua',
    'Last 30 Days': '30 ngày qua',
    'Last 90 Days': '90 ngày qua',
    'Last 1 Year': '1 năm qua',
    'By group': 'Theo nhóm',
    'By country': 'Theo quốc gia',
    'Latest Victims': 'Nạn nhân mới nhất',
    'Get help': 'Nhận trợ giúp',
    'Victim Count': 'Số nạn nhân',
    'Attack Count': 'Số vụ tấn công',
    'First Seen': 'Phát hiện lần đầu',
    'Last Seen': 'Phát hiện lần cuối',
    'Country Distribution': 'Phân bố Quốc gia',
    'Sector Distribution': 'Phân bố Lĩnh vực',
    'Cyberattacks': 'Tấn công mạng',
    'Breach Date': 'Ngày Rò rỉ',
    'Compromised Data Classes': 'Loại Dữ liệu Bị rò rỉ',

    // ── Tác nhân đe dọa ────────────────────────────────────────────────────────
    'Threat Actor': 'Tác nhân Đe dọa',
    'Threat Actors': 'Tác nhân Đe dọa',
    'All Threat Actors': 'Tất cả Tác nhân Đe dọa',
    'Campaign Context': 'Bối cảnh Chiến dịch',
    'Affiliation Score': 'Điểm Liên kết',
    'Attribution Dossier': 'Hồ sơ Quy trách nhiệm',
    'AI Assessment': 'Đánh giá AI',
    'Assessment Confidence': 'Độ tin cậy Đánh giá',
    'Attrib': 'Quy trách',
    'Attributes': 'Thuộc tính',
    'Contributors': 'Đóng góp',

    // ── YARA ────────────────────────────────────────────────────────────────────
    'Rule Explorer': 'Khám phá Quy tắc YARA',
    'Sample Scanner': 'Quét Mẫu YARA',
    'Rule Workbench': 'Bàn làm việc YARA',
    'YARA Rules': 'Quy tắc YARA',
    'Crowdsourced Rules': 'Quy tắc Cộng đồng',
    'Scan Results': 'Kết quả Quét',
    'Detection Content': 'Nội dung Phát hiện',
    'Validate': 'Xác thực',
    'Validation': 'Xác thực',
    'Test': 'Kiểm thử',
    'AI YARA Assistant': 'Trợ lý YARA AI',
    'Explain Rule': 'Giải thích Quy tắc',
    'Fix Rule': 'Sửa Quy tắc',
    'Auto Fix': 'Tự động Sửa',
    'Detection names': 'Tên phát hiện',

    // ── Tương đồng (Similarity) ────────────────────────────────────────────────
    'Similarity Dashboard': 'Bảng điều khiển Tương đồng',
    'Entity': 'Thực thể',
    'All Entities': 'Tất cả Thực thể',
    'Create Entity': 'Tạo Thực thể',
    'Compare Sample': 'So sánh Mẫu',
    'Compare Unknown Sample': 'So sánh Mẫu Chưa biết',
    'Similarity Score': 'Điểm Tương đồng',
    'Feature Extraction': 'Trích xuất Đặc trưng',
    'Static Features': 'Đặc trưng Tĩnh',
    'IDA Features': 'Đặc trưng IDA',
    'Basic Blocks': 'Khối cơ bản',
    'API Patterns': 'Mẫu API',
    'Threshold': 'Ngưỡng',
    'Match Score': 'Điểm Khớp',
    'Show samples and offsets': 'Hiển thị mẫu và offset',

    // ── Phân tích Nhị phân (Binary Lab) ───────────────────────────────────────
    'AI Binary Analysis Lab': 'Phòng thí nghiệm Phân tích Nhị phân AI',
    'BINARY ANALYSIS ENGINE': 'ENGINE PHÂN TÍCH NHỊ PHÂN',
    'ANALYSIS JOB': 'CÔNG VIỆC PHÂN TÍCH',
    'CURRENT STAGE': 'GIAI ĐOẠN HIỆN TẠI',
    'Analysis Jobs': 'Công việc Phân tích',
    'Analysis Time': 'Thời gian Phân tích',
    'Backend processing log': 'Nhật ký xử lý Backend',
    'AI Renamed': 'AI Đã đổi tên',
    'AI Renamed Only': 'Chỉ AI Đổi tên',
    'C Source Decompile': 'Dịch ngược C',
    'CTI REPORT': 'BÁO CÁO CTI',
    'CTI Reporting': 'Báo cáo CTI',
    'Disassembler Log': 'Nhật ký Trình dịch hợp ngữ',
    'Disassemble': 'Dịch hợp ngữ',
    'Decompile': 'Dịch ngược',
    'Function Rename': 'Đổi tên Hàm',
    'Variable Rename': 'Đổi tên Biến',
    'Autonomous Analysis': 'Phân tích Tự động',
    'Workspace Export': 'Xuất Workspace',
    'Export AI Workspace': 'Xuất AI Workspace',
    'Multi-Format Report': 'Báo cáo Đa định dạng',
    'Capabilities': 'Khả năng',
    'Carrier': 'Carrier',
    'Choose input': 'Chọn đầu vào',

    // ── Săn hạ tầng (Infra Hunt) ───────────────────────────────────────────────
    'Infrastructure Hunt Engine': 'Công cụ Săn Cơ sở hạ tầng',
    'C2 Playbooks': 'Playbook C2',
    'C2 Catalog': 'Danh mục C2',
    'Hunter Deck': 'Bộ công cụ Săn',
    'Fingerprint': 'Dấu vân tay',
    'Fingerprints': 'Dấu vân tay',
    'Candidate Indicator': 'Chỉ số Ứng viên',
    'Scoring': 'Tính điểm',
    'Expansion engines': 'Công cụ mở rộng',
    'Signals per query': 'Tín hiệu mỗi truy vấn',
    'Correlated Evidence': 'Bằng chứng Tương quan',
    'Start with an IP, domain, ASN, CIDR, certificate fingerprint, JARM, or provider query.': 'Bắt đầu với IP, tên miền, ASN, CIDR, dấu vân tay chứng chỉ, JARM...',
    'Seed enrichment automatically uses selected passive sources; expansion engines above are queried only after preview.': 'Làm giàu hạt nhân tự động sử dụng nguồn thụ động đã chọn; công cụ mở rộng được truy vấn chỉ sau khi xem trước.',
    'ACTIVE: getMe - confirms token is live': 'ACTIVE: getMe - xác nhận token còn hoạt động',
    'ACTIVE: starts Telegram collection': 'ACTIVE: bắt đầu thu thập Telegram',
    'Fill the Dump Messages form (no Telegram contact)': 'Điền form Xuất Tin nhắn (không cần liên hệ Telegram)',
    'Remove this bot and all its collected data': 'Xóa bot này và tất cả dữ liệu đã thu thập',
    'Collection interval minutes': 'Chu kỳ thu thập (phút)',
    'Show ${escapeHtml(label)} list': 'Hiển thị danh sách ${label}',

    // ── Tình báo Lỗ hổng (Vuln Intelligence) ──────────────────────────────────
    'Vulnerability Intelligence': 'Tình báo Lỗ hổng Bảo mật',
    'CVE & Exploit Intelligence': 'Tình báo CVE & Khai thác',
    'OSV Malicious Packages (Supply Chain)': 'Gói Độc hại OSV (Chuỗi cung ứng)',
    'CVEs Indexed': 'CVE đã lập chỉ mục',
    'With PoCs': 'Có PoC',
    'Actively Exploited': 'Đang bị Khai thác',
    'OSV Malicious': 'Gói Độc hại OSV',
    'Trending PoCs': 'PoC Thịnh hành',
    'PoC Available': 'Có PoC',
    'KEV': 'KEV (Đang khai thác)',
    'Published': 'Đã xuất bản',
    'Modified': 'Đã sửa đổi',
    'STARS': 'SAO',
    'UPDATED': 'CẬP NHẬT',
    'NAME': 'TÊN',
    'DESCRIPTION': 'MÔ TẢ',
    'NEWEST': 'MỚI NHẤT',
    'MOST POCS': 'NHIỀU POC NHẤT',
    'GITHUB': 'GITHUB',
    'NUCLEI': 'NUCLEI',
    'METASPLOIT': 'METASPLOIT',
    'EXPLOITDB': 'EXPLOITDB',
    'VULHUB': 'VULHUB',
    'All Ecosystems': 'Tất cả Hệ sinh thái',
    'PACKAGE / MALICIOUS ID': 'GÓI / ID ĐỘC HẠI',
    'SUMMARY / INTENDED IMPACT': 'TÓM TẮT / TÁC ĐỘNG DỰ KIẾN',
    'MODIFIED': 'ĐÃ SỬA ĐỔI',

    // ── X Monitor ─────────────────────────────────────────────────────────────
    'Social threat intelligence': 'Tình báo đe dọa từ mạng xã hội',
    'Monitor selected public X accounts like a threat-intelligence timeline deck.': 'Theo dõi tài khoản X công khai như bảng tình báo mối đe dọa.',
    'All accounts': 'Tất cả tài khoản',
    'All post types': 'Tất cả loại bài đăng',
    'Contains URL': 'Chứa URL',
    'Contains Domain': 'Chứa tên miền',
    'Contains IP': 'Chứa địa chỉ IP',
    'Contains Hash': 'Chứa mã băm',
    'Contains CVE': 'Chứa CVE',
    'Has Media': 'Có Media',
    'Newest': 'Mới nhất',
    'Oldest': 'Cũ nhất',
    'Custom': 'Tùy chỉnh',

    // ── Giám sát Rò rỉ (Breach Watcher) ──────────────────────────────────────
    'Breach Watcher': 'Giám sát Rò rỉ Dữ liệu',
    'Recent Breaches': 'Vụ Rò rỉ Gần đây',
    'Breach Details': 'Chi tiết Vụ Rò rỉ',
    'Exposed Records': 'Bản ghi Bị lộ',
    'Data Classes': 'Loại Dữ liệu',
    'Verified': 'Đã xác minh',
    'Unverified': 'Chưa xác minh',
    'Fabricated': 'Giả mạo',
    'Sensitive': 'Nhạy cảm',
    'Pwned': 'Bị xâm phạm',
    'Is Spamlist': 'Danh sách Spam',
    'Domain Search': 'Tìm theo Tên miền',
    'Email Search': 'Tìm theo Email',

    // ── Telegram Toolkit ───────────────────────────────────────────────────────
    'Channel Monitor': 'Giám sát Kênh',
    'Telegram Auth Settings': 'Cài đặt Xác thực Telegram',
    'Bot Info': 'Thông tin Bot',
    'Dump Messages': 'Xuất Tin nhắn',
    'MTProto Session': 'Phiên MTProto',
    'Bot Token': 'Token Bot',
    'Phone Number': 'Số điện thoại',
    'Session String': 'Chuỗi phiên',
    'All bots': 'Tất cả bot',
    'All accounts': 'Tất cả tài khoản',
    'No messages': 'Không có tin nhắn',
    'Stealer Logs': 'Nhật ký Stealer',
    'Artifact Analysis': 'Phân tích Tạo tác',
    'Exposure Stats': 'Thống kê Phơi lộ',

    // ── Metis AI Panel ────────────────────────────────────────────────────────
    'Metis AI': 'Metis AI',
    'MANTIS AI': 'Metis AI',
    'Threat intelligence search and reasoning': 'Tìm kiếm và suy luận tình báo mối đe dọa',
    'Assist': 'Hỗ trợ',
    'Summarize Findings': 'Tóm tắt Kết quả',
    'Recommend Pivots': 'Đề xuất Hướng điều tra',
    'Compare Relationship': 'So sánh Mối quan hệ',
    'Attribution': 'Quy trách nhiệm',
    'Agent Investigation': 'Điều tra Tự động',
    'Draft Report': 'Soạn Báo cáo',
    'Hash, domain, IP, URL, malware family, threat actor, campaign, TTP, or multiple same-type IoCs': 'Mã băm, tên miền, IP, URL, họ phần mềm độc hại, tác nhân, TTP hoặc nhiều IoC cùng loại',
    'Summarize': 'Tóm tắt',
    'Pivots': 'Hướng điều tra',
    'Open panel': 'Mở bảng',
    'AEAD Case': 'Vụ việc AEAD',
    'AI Assessment': 'Đánh giá AI',
    'Case Report': 'Báo cáo Vụ việc',
    'Agent': 'Tác nhân tự động',
    'Case': 'Vụ việc',

    // ── Tải xuống mẫu ─────────────────────────────────────────────────────────
    'VirusTotal Intelligence': 'Tình báo VirusTotal',
    'Samples Downloader': 'Tải xuống Mẫu',
    'Sample hashes': 'Mã băm mẫu',
    'Enter up to 50 MD5, SHA-1, or SHA-256 hashes, separated by spaces, commas, or new lines.': 'Nhập tối đa 50 mã băm MD5, SHA-1 hoặc SHA-256, cách nhau bằng dấu cách, dấu phẩy hoặc xuống dòng.',
    'No hashes entered.': 'Chưa nhập mã băm nào.',
    'Save samples directly': 'Lưu mẫu trực tiếp',
    'Destination folder': 'Thư mục đích',
    'No folder selected': 'Chưa chọn thư mục',
    'I understand these files may contain active malware and will handle them in an isolated environment.': 'Tôi hiểu các tệp này có thể chứa phần mềm độc hại và sẽ xử lý trong môi trường cô lập.',
    'Download Results': 'Kết quả Tải xuống',
    'Waiting for input': 'Đang chờ nhập liệu',
    'No download attempts yet.': 'Chưa có lần tải nào.',
    'Sample download requires VirusTotal Premium / Intelligence privileges.': 'Tải mẫu yêu cầu đặc quyền VirusTotal Premium / Intelligence.',

    // ── CTI Articles ───────────────────────────────────────────────────────────
    'CTI Articles': 'Bài báo CTI',
    'Article': 'Bài báo',
    'Feed': 'Nguồn cấp',
    'Feeds': 'Nguồn cấp',
    'Enable Feed': 'Bật nguồn cấp',
    'Disable Feed': 'Tắt nguồn cấp',
    'Sync Feeds': 'Đồng bộ nguồn cấp',
    'AI Summary': 'Tóm tắt AI',
    'AI CTI Summary': 'Tóm tắt CTI AI',
    'Read More': 'Đọc thêm',
    'Open Article': 'Mở bài báo',
    'Extracted IOCs': 'IOC đã trích xuất',
    'No articles found': 'Không tìm thấy bài báo',
    'Last synced': 'Đồng bộ lần cuối',
    'DNS Lookups': 'Tra cứu DNS',
    'DNS OBSERVATIONS': 'QUAN SÁT DNS',
    'Coordinates': 'Tọa độ',
    'AS Name': 'Tên AS',
    'ASCII': 'ASCII',
    'Databases': 'Cơ sở dữ liệu',
    'Abuse Score': 'Điểm Lạm dụng',
    'CIDR Abuse Intelligence': 'Tình báo Lạm dụng CIDR',
    'CIDR Banner Intelligence': 'Tình báo Banner CIDR',

    // ── Claims & Evidence ──────────────────────────────────────────────────────
    'Claims': 'Tuyên bố',
    'Activity': 'Hoạt động',
    'Campaign Context': 'Bối cảnh Chiến dịch',
    'Associated IOCs': 'IOC liên quan',
    'Supporting': 'Ủng hộ',
    'Missing Evidence': 'Thiếu Bằng chứng',
    'Confidence Band': 'Dải Độ tin cậy',
    'High Confidence': 'Độ tin cậy Cao',
    'Medium Confidence': 'Độ tin cậy Trung bình',
    'Low Confidence': 'Độ tin cậy Thấp',
    'No Match': 'Không khớp',
    'Possible Match': 'Có thể Khớp',
    'Likely Match': 'Nhiều khả năng Khớp',
    'Strong Match': 'Khớp mạnh',
    'Add User': 'Thêm người dùng',

    // ── Misc UI ────────────────────────────────────────────────────────────────
    'Collapse Sidebar': 'Thu gọn Sidebar',
    'Expand Sidebar': 'Mở rộng Sidebar',
    'Toggle Sidebar Menu': 'Chuyển đổi Menu Sidebar',
    'Go to Metis Home': 'Về Trang chủ Metis',
    'CLICK TO ENTER': 'NHẤN ĐỂ BẮT ĐẦU',
    'GLOBAL INTELLIGENCE': 'TÌNH BÁO TOÀN CẦU',
    'THREAT ACTORS': 'TÁC NHÂN ĐE DỌA',
    'INFRASTRUCTURE': 'CƠ SỞ HẠ TẦNG',
    'MALWARE CAMPAIGNS': 'CHIẾN DỊCH PHẦN MỀM ĐỘC HẠI',
    'OPEN SOURCES': 'NGUỒN MỞ',
    'THREAT FEEDS': 'NGUỒN CẤP ĐE DỌA',
    'MULTI-SOURCE': 'ĐA NGUỒN',
    'REAL-TIME INSIGHTS': 'THÔNG TIN THỜI GIAN THỰC',
    'Feed Name': 'Tên nguồn cấp',
    'Records': 'Bản ghi',
    'The following sources do not require an API key': 'Các nguồn sau không cần khóa API',
    'Enable or disable threat intelligence feeds.': 'Bật hoặc tắt nguồn cấp tình báo mối đe dọa.',
    'Dynamic feeds are synced from the ThreatIntelFeeds directory.': 'Nguồn cấp động được đồng bộ từ thư mục ThreatIntelFeeds.',
    'Infra Hunt': 'Săn Hạ tầng',
    'Infra Hunt & C2 Catalog': 'Săn Hạ tầng & Danh mục C2',
    'Save Results': 'Lưu Kết quả',
    'Import JSON': 'Nhập JSON',
    'All Sources': 'Tất cả Nguồn',
    'No Source Selected': 'Chưa chọn Nguồn',
    'any': 'bất kỳ',
    'Any Date': 'Bất kỳ ngày',
    'Any': 'Bất kỳ',
  };

  // ─── Engine dịch tự động ─────────────────────────────────────────────────────

  let _enabled = localStorage.getItem('metis_lang') !== 'en';

  /** Dịch một chuỗi nếu tồn tại trong từ điển */
  function translate(text) {
    if (!text) return text;
    const trimmed = text.trim();
    if (VI[trimmed]) return VI[trimmed];
    // Thử không phân biệt hoa thường cho chuỗi ngắn
    if (trimmed.length < 60) {
      const lower = trimmed.toLowerCase();
      for (const [k, v] of Object.entries(VI)) {
        if (k.toLowerCase() === lower) return v;
      }
    }
    return text;
  }

  /** Dịch một text node */
  function translateNode(node) {
    if (!_enabled) return;
    if (node.nodeType !== Node.TEXT_NODE) return;
    const original = node.textContent;
    const trimmed = original.trim();
    if (!trimmed || trimmed.length < 2) return;
    const translated = translate(trimmed);
    if (translated !== trimmed) {
      node.textContent = original.replace(trimmed, translated);
    }
  }

  /** Dịch thuộc tính (title, placeholder, aria-label) của element */
  function translateAttrs(el) {
    if (!_enabled) return;
    ['title', 'placeholder', 'aria-label', 'data-tooltip'].forEach(attr => {
      const val = el.getAttribute && el.getAttribute(attr);
      if (val) {
        const t = translate(val.trim());
        if (t !== val.trim()) el.setAttribute(attr, t);
      }
    });
  }

  /** Dịch toàn bộ subtree */
  function translateSubtree(root) {
    if (!_enabled) return;
    // Thuộc tính của root
    if (root.nodeType === Node.ELEMENT_NODE) translateAttrs(root);
    // Walker qua tất cả text node
    const walker = document.createTreeWalker(
      root,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const p = node.parentElement;
          if (!p) return NodeFilter.FILTER_REJECT;
          // Bỏ qua script, style, code, pre, input, textarea
          const tag = p.tagName.toLowerCase();
          if (['script','style','code','pre','input','textarea','select'].includes(tag))
            return NodeFilter.FILTER_REJECT;
          // Bỏ qua placeholder (đã xử lý qua attrs)
          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );
    let node;
    const nodes = [];
    while ((node = walker.nextNode())) nodes.push(node);
    nodes.forEach(translateNode);
    // Thuộc tính của tất cả elements
    root.querySelectorAll && root.querySelectorAll('*').forEach(translateAttrs);
  }

  /** Dịch toàn bộ trang */
  function translateAll() {
    translateSubtree(document.body);
  }

  // ─── MutationObserver: theo dõi mọi thay đổi DOM ─────────────────────────────
  let _pendingNodes = [];
  let _scheduled = false;

  function scheduleFlush() {
    if (_scheduled) return;
    _scheduled = true;
    requestAnimationFrame(() => {
      _scheduled = false;
      const nodes = _pendingNodes.splice(0);
      nodes.forEach(n => {
        if (n.isConnected) translateSubtree(n);
      });
    });
  }

  const observer = new MutationObserver(mutations => {
    if (!_enabled) return;
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        _pendingNodes.push(node);
      }
      if (m.type === 'characterData') {
        translateNode(m.target);
      }
    }
    if (_pendingNodes.length) scheduleFlush();
  });

  // ─── API công khai ────────────────────────────────────────────────────────────
  window.MetisI18n = {
    /** Chuyển ngôn ngữ */
    setLang(lang) {
      _enabled = (lang === 'vi');
      localStorage.setItem('metis_lang', lang);
      if (_enabled) {
        translateAll();
      } else {
        // Reload trang để khôi phục tiếng Anh (đơn giản nhất)
        location.reload();
      }
      this._updateToggleBtn();
    },
    getLang() { return _enabled ? 'vi' : 'en'; },
    _updateToggleBtn() {
      const btn = document.getElementById('metis-lang-toggle');
      if (!btn) return;
      if (_enabled) {
        btn.innerHTML = '🇻🇳 Tiếng Việt';
        btn.title = 'Chuyển sang English';
      } else {
        btn.innerHTML = '🇬🇧 English';
        btn.title = 'Switch to Tiếng Việt';
      }
    },
    translate,
  };

  // ─── Khởi động ────────────────────────────────────────────────────────────────
  function init() {
    // Bắt đầu quan sát DOM
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
    });

    // Dịch trang hiện tại
    if (_enabled) translateAll();

    // Cập nhật nút ngôn ngữ
    window.MetisI18n._updateToggleBtn();

    // Nút chuyển ngôn ngữ — sự kiện click
    document.addEventListener('click', e => {
      const btn = e.target.closest('#metis-lang-toggle');
      if (!btn) return;
      window.MetisI18n.setLang(_enabled ? 'en' : 'vi');
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
