document.addEventListener('DOMContentLoaded', function () {
    function createChart(ctxId, type, data, options) {
        const ctx = document.getElementById(ctxId).getContext('2d');
        try {
            return new Chart(ctx, {
                type: type,
                data: data,
                options: {
                    ...options,
                    animation: {
                        duration: 1000,
                        easing: 'easeOutQuart'
                    },
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        } catch (error) {
            console.error(`Error creating ${ctxId} chart:`, error);
            return null;
        }
    }

    function getParsedData(elementId) {
        const element = document.getElementById(elementId);
        if (!element) {
            console.error(`${elementId} element not found`);
            return [];
        }
        try {
            return JSON.parse(element.textContent) || '{}';
        } catch (error) {
            console.error(`Error parsing ${elementId} JSON:`, error, element.textContent);
            return [];
        }
    }

    // Events by Council Chart
    const eventsData = getParsedData('eventsData');
    const eventsChart = createChart('eventsChart', 'bar', {
        labels: eventsData.map(item => item.council_name || 'Unknown'),
        datasets: [{
            label: eventsData.map(item => item.council_name || item.count),
            data: eventsData.map(item => item.count || 0),
            backgroundColor: 'rgba(250, 204, 21, 0.6)', // Yellow to match theme
            borderColor: 'rgba(250, 204, 21, 1)',
            borderWidth: 1
        }]
    }, {
        scales: {
            y: { beginAtZero: true, title: { display: true, text: 'Number of Events', color: '#e0e7ff' } },
            x: { title: { display: true, text: 'Council', color: '#e0e7ff' } }
        },
        plugins: {
            title: {
                display: true,
                text: document.getElementById('selectedCouncil').value ? `Number of Approved Events for ${eventsData[0]?.council_name || 'Unknown'}` : 'Total Number of Approved Events by Council',
                color: '#facc15'
            },
            legend: { labels: { color: '#e0e7ff' }, display: eventsData.length > 0 }
        }
    });
    if (eventsData.length === 0 && eventsChart) {
        eventsChart.data.datasets[0].data = [0];
        eventsChart.data.labels = ['No Data'];
        eventsChart.update();
    }

    // Donations Per Month Chart
    const donationsData = getParsedData('donationsData');
    const donationsChart = createChart('donationsChart', 'line', {
        labels: donationsData.map(item => item.month || 'Unknown'),
        datasets: [{
            label: 'Donation Amount (PHP)',
            data: donationsData.map(item => item.total || 0),
            fill: false,
            borderColor: 'rgba(34, 197, 94, 1)', // Green
            tension: 0.1
        }]
    }, {
        scales: {
            y: { beginAtZero: true, title: { display: true, text: 'Donation Amount (PHP)', color: '#e0e7ff' } },
            x: { title: { display: true, text: 'Month', color: '#e0e7ff' } }
        },
        plugins: {
            title: {
                display: true,
                text: document.getElementById('selectedCouncil').value ? `Donations Per Month for ${eventsData[0]?.council_name || 'Unknown'}` : 'Total Donations Per Month',
                color: '#facc15'
            },
            legend: { labels: { color: '#e0e7ff' }, display: donationsData.length > 0 }
        }
    });
    if (donationsData.length === 0 && donationsChart) {
        donationsChart.data.datasets[0].data = [0];
        donationsChart.data.labels = ['No Data'];
        donationsChart.update();
    }

    // Members and Officers Chart
    const membersOfficersData = getParsedData('membersOfficersData');
    const membersOfficersChart = createChart('membersOfficersChart', 'bar', {
        labels: membersOfficersData.map(item => item.council_name || 'Unknown'),
        datasets: [
            { label: 'Members', data: membersOfficersData.map(item => item.members || 0), backgroundColor: 'rgba(59, 130, 246, 0.6)', borderColor: 'rgba(59, 130, 246, 1)', borderWidth: 1 },
            { label: 'Officers', data: membersOfficersData.map(item => item.officers || 0), backgroundColor: 'rgba(234, 179, 8, 0.6)', borderColor: 'rgba(234, 179, 8, 1)', borderWidth: 1 }
        ]
    }, {
        scales: {
            x: { stacked: true, title: { display: true, text: 'Council', color: '#e0e7ff' } },
            y: { stacked: true, beginAtZero: true, title: { display: true, text: 'Number of Users', color: '#e0e7ff' } }
        },
        plugins: {
            title: {
                display: true,
                text: document.getElementById('selectedCouncil').value ? `Members and Officers in ${membersOfficersData[0]?.council_name || 'Unknown'}` : 'Total Members and Officers by Council',
                color: '#facc15'
            },
            legend: { labels: { color: '#e0e7ff' }, display: membersOfficersData.length > 0 }
        }
    });
    if (membersOfficersData.length === 0 && membersOfficersChart) {
        membersOfficersChart.data.datasets[0].data = [0];
        membersOfficersChart.data.datasets[1].data = [0];
        membersOfficersChart.data.labels = ['No Data'];
        membersOfficersChart.update();
    }

    // Event Types Distribution Chart
    const eventTypesData = getParsedData('eventTypesData');
    const eventTypesChart = createChart('eventTypesChart', 'pie', {
        labels: eventTypesData.map(item => item.category || 'Unknown'),
        datasets: [{
            label: 'Event Types',
            data: eventTypesData.map(item => item.count || 0),
            backgroundColor: [
                'rgba(239, 68, 68, 0.6)',  // Red
                'rgba(59, 130, 246, 0.6)', // Blue
                'rgba(34, 197, 94, 0.6)',  // Green
                'rgba(234, 179, 8, 0.6)',  // Yellow
            ],
            borderColor: [
                'rgba(239, 68, 68, 1)',
                'rgba(59, 130, 246, 1)',
                'rgba(34, 197, 94, 1)',
                'rgba(234, 179, 8, 1)',
            ],
            borderWidth: 1
        }]
    }, {
        plugins: {
            title: {
                display: true,
                text: document.getElementById('selectedCouncil').value ? `Event Types for ${eventsData[0]?.council_name || 'Unknown'}` : 'Event Types Distribution',
                color: '#facc15'
            },
            legend: { labels: { color: '#e0e7ff' }, display: eventTypesData.length > 0 }
        }
    });
    if (eventTypesData.length === 0 && eventTypesChart) {
        eventTypesChart.data.datasets[0].data = [0];
        eventTypesChart.data.labels = ['No Data'];
        eventTypesChart.update();
    }

    // Donation Sources Chart
    const donationSourcesData = getParsedData('donationSourcesData');
    const donationSourcesChart = createChart('donationSourcesChart', 'doughnut', {
        labels: donationSourcesData.map(item => item.payment_method || 'Unknown'),
        datasets: [{
            label: 'Donation Amount (PHP)',
            data: donationSourcesData.map(item => item.amount || 0),
            backgroundColor: [
                'rgba(239, 68, 68, 0.6)',
                'rgba(59, 130, 246, 0.6)',
                'rgba(34, 197, 94, 0.6)',
            ],
            borderColor: [
                'rgba(239, 68, 68, 1)',
                'rgba(59, 130, 246, 1)',
                'rgba(34, 197, 94, 1)',
            ],
            borderWidth: 1
        }]
    }, {
        plugins: {
            title: {
                display: true,
                text: document.getElementById('selectedCouncil').value ? `Donation Sources for ${eventsData[0]?.council_name || 'Unknown'}` : 'Donation Sources',
                color: '#facc15'
            },
            legend: { labels: { color: '#e0e7ff' }, display: donationSourcesData.length > 0 }
        }
    });
    if (donationSourcesData.length === 0 && donationSourcesChart) {
        donationSourcesChart.data.datasets[0].data = [0];
        donationSourcesChart.data.labels = ['No Data'];
        donationSourcesChart.update();
    }

    // Member Activity Chart
    const memberActivityData = getParsedData('memberActivityData');
    const labels = memberActivityData.map(item => item.category || 'Unknown');
    const activeCounts = labels.map(label => {
        const item = memberActivityData.find(data => data.category === label);
        return label === 'Active Members' ? (item?.count || 0) : 0;
    });
    const inactiveCounts = labels.map(label => {
        const item = memberActivityData.find(data => data.category === label);
        return label === 'Inactive Members' ? (item?.count || 0) : 0;
    });
    const memberActivityChart = createChart('memberActivityChart', 'bar', {
        labels: labels,
        datasets: [{
            label: 'Active Members',
            data: activeCounts,
            backgroundColor: 'rgba(34, 197, 94, 0.6)', // Green for Active
            borderColor: 'rgba(34, 197, 94, 1)',
            borderWidth: 1
        }, {
            label: 'Inactive Members',
            data: inactiveCounts,
            backgroundColor: 'rgba(239, 68, 68, 0.6)', // Red for Inactive
            borderColor: 'rgba(239, 68, 68, 1)',
            borderWidth: 1
        }]
    }, {
        scales: {
            y: { beginAtZero: true, title: { display: true, text: 'Number of Members', color: '#e0e7ff' } },
            x: { title: { display: true, text: 'Category', color: '#e0e7ff' } }
        },
        plugins: {
            title: {
                display: true,
                text: document.getElementById('selectedCouncil').value ? `Member Activity for ${eventsData[0]?.council_name || 'Unknown'}` : 'Member Activity',
                color: '#facc15'
            },
            legend: { labels: { color: '#e0e7ff' }, display: true }
        }
    });
    if (memberActivityData.length === 0 && memberActivityChart) {
        memberActivityChart.data.datasets[0].data = [0];
        memberActivityChart.data.datasets[1].data = [0];
        memberActivityChart.data.labels = ['No Data'];
        memberActivityChart.update();
    }
// Mobile: Click ? to toggle tooltip
document.querySelectorAll('.help-icon').forEach(icon => {
    icon.addEventListener('click', function(e) {
        e.stopPropagation();
        this.classList.toggle('active');
    });
});

// Close all on click outside
document.addEventListener('click', () => {
    document.querySelectorAll('.help-icon.active').forEach(el => el.classList.remove('active'));
});

const style = document.createElement('style');
style.textContent = `
    .help-icon.active::after,
    .help-icon.active::before {
        opacity: 1 !important;
        visibility: visible !important;
    }
    .help-icon.active::after {
        bottom: 150% !important;
    }
`;
document.head.appendChild(style);
});