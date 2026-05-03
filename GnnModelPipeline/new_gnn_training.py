import torch.nn as nn
import torch
from torch_geometric.nn import SAGEConv
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, f1_score


class GNNModel(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes):
        super().__init__()

        self.conv1 = SAGEConv(input_dim, hidden_dim)
        self.conv2 = SAGEConv(hidden_dim, hidden_dim)

        self.dropout = nn.Dropout(0.3)

        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, data):
        x, edge_index = data.x, data.edge_index


        x = self.conv1(x, edge_index)
        x = self.bn1(x)
        x = F.relu(x)
        x = self.dropout(x)

        x = self.conv2(x, edge_index)
        x = self.bn2(x)
        x = F.relu(x)
        x = self.dropout(x)

        return self.fc(x)


def save_gnn_model(model, path="gnn_model.pt"):
    torch.save(model.state_dict(), path)
    print(f"GNN model saved at {path}")


def add_train_mask(data, train_ratio=0.8):
    n = data.num_nodes
    mask = torch.zeros(n, dtype=torch.bool)

    idx = torch.randperm(n)[:int(train_ratio * n)]
    mask[idx] = True

    data.train_mask = mask
    data.test_mask = ~mask

    return data

def train_and_evaluate(train_data, test_data, model_path):

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    train_data = train_data.to(device)
    test_data = test_data.to(device)

    model = GNNModel(train_data.x.shape[1], 64, 4).to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    # ✅ Class weights
    class_counts = torch.bincount(train_data.y)
    weights = 1.0 / class_counts.float()
    weights = weights / weights.sum()

    loss_fn = nn.CrossEntropyLoss(weight=weights.to(device))

    for epoch in range(50):

        model.train()
        optimizer.zero_grad()

        out = model(train_data)
        loss = loss_fn(out, train_data.y)

        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 2.0)
        optimizer.step()

        pred = out.argmax(dim=1).cpu()
        true = train_data.y.cpu()

        acc = accuracy_score(true, pred)
        f1 = f1_score(true, pred, average="weighted")

        print(f"Epoch {epoch} | Loss: {loss.item():.4f} | Acc: {acc:.4f} | F1: {f1:.4f}")

    save_gnn_model(model, model_path)

    # -------- TEST --------
    model.eval()
    with torch.no_grad():
        out = model(test_data)

        pred = out.argmax(dim=1).cpu()
        true = test_data.y.cpu()

        acc = accuracy_score(true, pred)
        f1 = f1_score(true, pred, average="weighted")

    print("\nTest Results:")
    print(f"Accuracy: {acc:.4f}")
    print(f"F1 Score: {f1:.4f}")

    return model